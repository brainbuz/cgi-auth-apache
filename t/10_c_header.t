use strict;
use warnings;
use Test::More;
use Time::Piece ;

BEGIN { use_ok 'Apache::Auth::Catalyst' } ;

package TestHash ;

sub new {
    my $class = shift ;
    my $setheader = shift ;
    my $headerval = shift ;
    my $self = {
                 'user-agent' => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0',
                 'connection' => 'close',
                 'cache-control' => 'max-age=0',
                 'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                 'accept-language' => 'en-US,en;q=0.5',
                 'accept-encoding' => 'gzip, deflate',
                 'dnt' => '1',
                 'x-forwarded-server' => 'calevt.bz',
                 'x-forwarded-host' => 'calevt.bz',
                 'host' => 'calevt.bz',
                 'x-forwarded-for' => '192.168.10.30',
                 $setheader => $headerval, 
               } ;
    bless $self , $class;
    $self->{ class } = $class ;
    return $self ;
}

sub header {
    my $self= shift ;
    my $header = shift ;
    return $self->{ $header } ;
    }

package main ;
               

delete $ENV{ remote_user } ;
my $undefhash = new TestHash( 'undef' => 'undef' ) ;

note( &Apache::Auth::Catalyst::Get( $undefhash ) ) ;
is( &Apache::Auth::Catalyst::Get( $undefhash ), undef , 
   'When no other values are passed no %ENV set, return undef.' );

$ENV{ remote_user } = 'mememe' ;
is( &Apache::Auth::Catalyst::Get( $undefhash ), 'mememe', 
   "When no other values are passed, \n     but a remote_user was set in %ENV it is user." );

delete $ENV{ remote_user };
my $digestTH = new TestHash(
    'authorization' => 
    'Digest username="digest_user", realm="calevt", nonce="uaS26fvoBAA=7168f0826aa684d6be3a64c32b2fc695d384a35c", uri="/debug/spew", algorithm=MD5, response="06adc2a66832a8f498b354ff14ab8a6f", qop=auth, nc=00000003, cnonce="2039391658c1ab66"' );
is( &Apache::Auth::Catalyst::Get( $digestTH ), 'digest_user', "Set user by digest." );

my $ruTH = TestHash->new( 'remote_user' => 'setbybasic' ) ;
is( &Apache::Auth::Catalyst::Get( $ruTH ), 'setbybasic', 
   "Set user by remote_user." );

my $RRU = TestHash->new( 'redirect_remote_user' => 'redirecteduser' ) ;
is( &Apache::Auth::Catalyst::Get( $RRU ), 'redirecteduser', 
    "Set user by redirect_remote_user." );

my $HXFU = new TestHash( 'HTTP_X_FORWARDED_USER' => 'userx' ) ;
is( &Apache::Auth::Catalyst::Get( $HXFU ), 'userx', 
   "Set by X Forwded User." );



done_testing();
