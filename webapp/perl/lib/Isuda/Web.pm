package Isuda::Web;
use 5.014;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Encode qw/encode_utf8/;
use POSIX qw/ceil/;
use Furl;
use JSON::XS qw/decode_json/;
use String::Random qw/random_string/;
use Digest::SHA1 qw/sha1_hex/;
use URI::Escape qw/uri_escape_utf8/;
use Text::Xslate::Util qw/html_escape/;
use List::Util qw/min max/;
use Cache::Memcached::Fast;

my $PER_PAGE = 10;

my $memd = Cache::Memcached::Fast->new({
    servers => [ { address => 'localhost:11211' }],
}); 

my %_sha1_cache;
sub _sha1_hex {
    my $key = shift;
    return $_sha1_cache{$key} ||= sha1_hex($key);
}

my %_sha1_utf8_cache;
sub _sha1_utf8_hex {
    my $word = shift;
    return $_sha1_utf8_cache{$word} ||= sha1_hex(encode_utf8($word));
}

sub config {
    state $conf = {
        dsn           => $ENV{ISUDA_DSN}         // 'dbi:mysql:db=isuda',
        db_user       => $ENV{ISUDA_DB_USER}     // 'root',
        db_password   => $ENV{ISUDA_DB_PASSWORD} // '',
        isutar_origin => $ENV{ISUTAR_ORIGIN}     // 'http://localhost:5001',
        isupam_origin => $ENV{ISUPAM_ORIGIN}     // 'http://localhost:5050',
    };
    my $key = shift;
    my $v = $conf->{$key};
    unless (defined $v) {
        die "config value of $key undefined";
    }
    return $v;
}

sub dbh {
    my ($self) = @_;
    return $self->{dbh} //= DBIx::Sunny->connect(config('dsn'), config('db_user'), config('db_password'), {
        Callbacks => {
            connected => sub {
                my $dbh = shift;
                $dbh->do(q[SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY']);
                $dbh->do('SET NAMES utf8mb4');
                return;
            },
        },
    });
}

filter 'set_name' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $user_id = $c->env->{'psgix.session'}->{user_id};
        if ($user_id) {
            $c->stash->{user_id} = $user_id;
            $c->stash->{user_name} = $self->dbh->select_one(q[
                SELECT name FROM user
                WHERE id = ?
            ], $user_id);
            $c->halt(403) unless defined $c->stash->{user_name};
        }
        $app->($self,$c);
    };
};

filter 'authenticate' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        $c->halt(403) unless defined $c->stash->{user_id};
        $app->($self,$c);
    };
};

get '/initialize' => sub {
    my ($self, $c)  = @_;
    $self->dbh->query(q[
        DELETE FROM entry WHERE id > 7101
    ]);
    $self->dbh->query('TRUNCATE star');

    # warm up
    $self->dbh->query('SELECT * FROM entry');
    $self->dbh->query('SELECT * FROM user');
    $self->dbh->query('SELECT * FROM star');

    $c->render_json({
        result => 'ok',
    });
};

get '/' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;

    my $page = $c->req->parameters->{page} || 1;

    my $entries = $self->dbh->select_all(qq[
        SELECT * FROM entry
        ORDER BY updated_at DESC
        LIMIT $PER_PAGE
        OFFSET @{[ $PER_PAGE * ($page-1) ]}
    ]);
    
    my $sort_keywords = $self->get_keywords_sort();
    my $keyword_stars_map = $self->load_stars([ map { $_->{keyword} } @$entries ]);
    foreach my $entry (@$entries) {
        $entry->{html}  = $self->htmlify($c, $sort_keywords, $entry->{description});
        $entry->{stars} = $keyword_stars_map->{$entry->{keyword}};
    }

    my $total_entries = $self->get_entries();

    my $last_page = ceil($total_entries / $PER_PAGE);
    my @pages = (max(1, $page-5)..min($last_page, $page+5));

    $c->render('index.tx', { entries => $entries, page => $page, last_page => $last_page, pages => \@pages });
};

get 'robots.txt' => sub {
    my ($self, $c)  = @_;
    $c->halt(404);
};

post '/keyword' => [qw/set_name authenticate/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->req->parameters->{keyword};
    unless (length $keyword) {
        $c->halt(400, q('keyword' required));
    }
    my $keyword_length = length $keyword;
    my $user_id = $c->stash->{user_id};
    my $description = $c->req->parameters->{description};

    if (is_spam_contents($description) || is_spam_contents($keyword)) {
        $c->halt(400, 'SPAM!');
    }
    $self->dbh->query(q[
        INSERT INTO entry (author_id, keyword, description, created_at, updated_at, keyword_length)
        VALUES (?, ?, ?, NOW(), NOW(), ?)
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, updated_at = NOW(), keyword_length = ?
    ], ($user_id, $keyword, $description, $keyword_length) x 2);

    # キャッシュに加算
    $c->env->{'psgix.session'}->{entry_count} = $self->get_entries(1);

    $c->redirect('/');
};

get '/register' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;
    $c->render('authenticate.tx', {
        action => 'register',
    });
};

post '/register' => sub {
    my ($self, $c) = @_;

    my $name = $c->req->parameters->{name};
    my $pw   = $c->req->parameters->{password};
    $c->halt(400) if $name eq '' || $pw eq '';

    my $user_id = register($self->dbh, $name, $pw);

    $c->env->{'psgix.session'}->{user_id} = $user_id;
    $c->redirect('/');
};

sub register {
    my ($dbh, $user, $pass) = @_;

    my $salt = random_string('....................');
    $dbh->query(q[
        INSERT INTO user (name, salt, password, created_at)
        VALUES (?, ?, ?, NOW())
    ], $user, $salt, _sha1_hex($salt . $pass));

    return $dbh->last_insert_id;
}

get '/login' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;
    $c->render('authenticate.tx', {
        action => 'login',
    });
};

post '/login' => sub {
    my ($self, $c) = @_;

    my $name = $c->req->parameters->{name};
    my $row = $self->dbh->select_row(q[
        SELECT * FROM user
        WHERE name = ?
    ], $name);
    if (!$row || $row->{password} ne _sha1_hex($row->{salt}.$c->req->parameters->{password})) {
        $c->halt(403)
    }

    $c->env->{'psgix.session'}->{user_id} = $row->{id};
    $c->redirect('/');
};

get '/logout' => sub {
    my ($self, $c)  = @_;
    $c->env->{'psgix.session'} = {};
    $c->redirect('/');
};

get '/keyword/:keyword' => [qw/set_name/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->args->{keyword} // $c->halt(400);

    my $entry = $self->dbh->select_row(qq[
        SELECT * FROM entry
        WHERE keyword = ?
    ], $keyword);
    $c->halt(404) unless $entry;
    my $sort_keywords = $self->get_keywords_sort();
    $entry->{html} = $self->htmlify($c, $sort_keywords, $entry->{description});
    my $keyword_stars_map = $self->load_stars([$entry->{keyword}]);
    $entry->{stars} = $keyword_stars_map->{$entry->{keyword}};

    $c->render('keyword.tx', { entry => $entry });
};

post '/keyword/:keyword' => [qw/set_name authenticate/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->args->{keyword} or $c->halt(400);
    $c->req->parameters->{delete} or $c->halt(400);

    my $result = $self->dbh->query(qq[
        DELETE FROM entry
        WHERE keyword = ?
    ], $keyword);
    unless ($result) {
        $c->halt(404);
    }

    # キャッシュから減算
    $c->env->{'psgix.session'}->{entry_count} = $self->get_entries(-1);

    $c->redirect('/');
};

post '/stars' => sub {
    my ($self, $c) = @_;
    my $keyword = $c->req->parameters->{keyword} or $c->halt(404);

    my $result = $self->dbh->query(q[
        INSERT INTO star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
    ], $keyword, $c->req->parameters->{user});
    unless ($result){
        $c->halt(404)
    }

    $c->render_json({
        result => 'ok',
    });
};

sub htmlify {
    my ($self, $c, $keywords, $content) = @_;
    return '' unless defined $content;
    my %kw2sha;
    my $re = $keywords;
    $content =~ s{($re)}{
        my $kw = $1;
        $kw2sha{$kw} = "isuda_" . _sha1_utf8_hex($kw);
    }eg;
    $content = html_escape($content);
    while (my ($kw, $hash) = each %kw2sha) {
        my $url = $c->req->uri_for('/keyword/' . uri_escape_utf8($kw));
        my $link = sprintf '<a href="%s">%s</a>', $url, html_escape($kw);
        $content =~ s/$hash/$link/g;
    }
    $content =~ s{\n}{<br \/>\n}gr;
}

sub load_stars {
    my ($self, $keywords) = @_;

    my $ids_in_str = join(',', ('?') x scalar @$keywords);
    my $stars = $self->dbh->select_all("
        SELECT * FROM star WHERE keyword IN ($ids_in_str)
    ", @$keywords);

    my $keyword_stars_map = +{};
    for my $star (@$stars) {
        $keyword_stars_map->{$star->{keyword}} ||= [];
        push @{$keyword_stars_map->{$star->{keyword}}}, $star;
    }
    return $keyword_stars_map;
}

sub is_spam_contents {
    my $content = shift;
    my $ua = Furl->new;
    my $res = $ua->post(config('isupam_origin'), [], [
        content => encode_utf8($content),
    ]);
    my $data = decode_json $res->content;
    !$data->{valid};
}

sub get_entries {
    my ($self, $num) = @_;

    my $entry_count = $self->dbh->select_one(q[
        SELECT COUNT(id) FROM entry
    ]);
    return $entry_count;
}

sub get_keywords_sort {
    my ($self) = @_;
     my $keywords = $self->dbh->select_all(qq[
        SELECT keyword FROM entry ORDER BY keyword_length DESC
    ]);

    my $re = join '|', map { quotemeta $_->{keyword} } @$keywords;
    $re;
}

1;
