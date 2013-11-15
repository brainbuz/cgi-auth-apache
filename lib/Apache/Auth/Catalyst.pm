package Apache::Auth::Catalyst ;

our $VERSION = '1.00';

sub Get {
    for ( $ENV{ remote_user } ) { return $_ if $_ }
    my $request = shift ; # $c->request->headers
    for ( $request->header( 'remote_user' ) ) { return $_ if $_ }
    for ( $request->header( 'redirect_remote_user' ) ) { return $_ if $_ }
    for ( $request->header( 'HTTP_X_FORWARDED_USER' ) ) {
        return $_ if $_ }
    my $digestname = $request->header( 'authorization' ) ;
    if( $digestname ) {
        $digestname =~ m/username(.*)realm/ ;
        $digestname =  $1 ;
        $digestname =~ s/\W//g ;
        return $digestname  ;
        }
    return undef;
    }

1;

=pod

=head1 NAME

ApacheUser - discover apache logged in user from commonly seen request headers.

=head1 VERSION

Version 1.00

=head1 Method: Get

Module has 1 method Get, pass it a reference to $c->request->headers to get back either the 
logged in user or undef. For testing purposes it will use $ENV{ remote_user }, so that you can
write controller tests by setting the user in %ENV before your test. 

Apache sets (or hides) the logged in user variable to different values in
different situations depending on which module is used, whether there is a 
rewrite rule involved and if the request is proxied. A valuable feature would be an override command to always set a specific header
to the username of the authenticated user. At present it is necessary to check
each deployment situation and in some cases to attempt to rewrite an environment
variable. This module already knows to check for some of the common variants, and 
it checks for HTTP_X_FORWARDED_USER if you need to attempt to rewrite.

Here is an example rewrite rule to set HTTP_X_FORWARDED_USER.

        RewriteCond %{LA-U:REMOTE_USER} (.+)
        RewriteRule ^.*$ - [E=RU:%1]
        RequestHeader add X-Forwarded-User %{RU}e


=head1 Usage

 use Apache::Auth::Catalyst;
 $c->stash( 
    remote_user 
    => &Apache::Auth::Catalyst::Get( $c->request->headers ) 
    );   

The above code is typically all you need, and if you place it into  Begin
 in your Root Controller $c->stash->{remote_user} will be globally available to
all of your controllers. 


=head1 AUTHOR

John Karr, C<< <brainbuz at brainbuz.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-string-validator-htmlutf8 at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=String-Validator-HTMLUTF8>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Apache::Auth::Catalyst

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Apache-Auth-Catalyst>

=item * Search CPAN

L<http://search.cpan.org/dist/Apache::Auth::Catalyst/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 John Karr.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see L<http://www.gnu.org/licenses/>.

=cut

1;