package HouseURL;
use MLDBM qw(DB_File);
use Digest::MD5 qw(md5_hex);

use Apache;
use Apache::Constants;


sub handler {
    my $r = shift;
    $r->path_info() =~ /([a-f0-9]{32})/ or return DECLINED;
    my $key = $1;
    my %o;
    tie %o, "MLDBM", "/opt/houseurl/data.db" or die $!;
    return DECLINED if !exists $o{$key};
    use Data::Dumper; warn Dumper($o{$key});
    my $stuff = $o{$key};
    $r->send_http_header("text/html");
    if ($stuff->{count}++) {
        intruder($r, $key, $stuff);
        untie %o;
        print "<HTML><HEAD>Unauthorized access</HEAD>
<BODY>
You are not authorized to access this resource. This attempt has been
recorded.
</BODY>
<HTML>";
        return OK;
    }
    $o{$key} = $stuff;
    use Data::Dumper; warn Dumper($o{$key});
    untie %o;
    open IN, "/opt/houseurl/text.html";
    local $/; print <IN>; close IN; return OK;
}

sub authorize {
    my $key = md5_hex(time().{}.rand().$$);
    my $comments = join " ", @ARGV;
    my %o;
    tie %o, "MLDBM", "/opt/houseurl/data.db" or die $!;
    $o{$key} = {
       comments => $comments,
       count => 0,
       created => time
    };
    untie %o;
    print "http://neo.trinity-house.org.uk/directions/$key\n";
}

sub intruder {
    my ($r, $key, $hash) = @_;
    use Mail::Send;
    my $msg = new Mail::Send To => 'simon@simon-cozens.org',
                             Subject => 'HouseURL Intruder';
    my $fh = $msg->open;
    print $fh <<EOF;

Key issued at @{[ scalar localtime $hash->{created} ]}
with comments @{[ $hash->{comments} ]}

Reused at @{[ scalar localtime ]}
by @{[ $r->get_remote_host ]} ( @{[ $r->get_remote_logname ]} )

EOF

    $fh->close;
}

1;

