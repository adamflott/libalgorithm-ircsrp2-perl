package Algorithm::IRCSRP2;

# ABSTRACT: IRC channel encryption algorithm

use Moose;

# core
use Data::Dumper;
use Digest::SHA;
use MIME::Base64;
use Math::BigInt only => 'GMP,Pari';

# CPAN
use Crypt::OpenSSL::AES;

# local
use Algorithm::IRCSRP2::Utils qw(:all);

has 'error' => (
    'isa' => 'Str',
    'is'  => 'rw',
);

has 'nickname' => (
    'isa'     => 'Str',
    'is'      => 'rw',
    'default' => 'unknown'
);

foreach my $p (qw(prefs_account prefs_channel prefs_dave_nick prefs_user prefs_password)) {
    has $p => (
        'isa' => 'Maybe[Str]',
        'is'  => 'rw',
    );
}

has 'debug_cb' => (
    'isa'     => 'CodeRef',
    'is'      => 'rw',
    'default' => sub {
        sub {
            my @args = @_;
            @args = grep { defined($_) } @args;
            print(@args);
          }
    }
);

has '_orig_debug_cb' => (
    'isa'     => 'CodeRef',
    'is'      => 'rw',
    'default' => sub {
        sub {
          }
    }
);

has 'am_i_dave' => (
    'isa' => 'Bool',
    'is'  => 'ro',
);

has 'cbc_blocksize' => (
    'isa'     => 'Int',
    'is'      => 'ro',
    'default' => 16
);

# -------- methods --------
sub BUILD {
    my ($self) = @_;

    my $orig_cb = $self->debug_cb;

    $self->_orig_debug_cb($orig_cb);

    my $new_cb = sub {
        my $str = join('', @_);
        $str = (($self->am_i_dave) ? 'Dave: ' : 'Alice: ') . $self->nickname . ' ' . $str;
        return $orig_cb->($str);
    };

    $self->debug_cb($new_cb);
}

sub init {
    my ($self) = @_;

    my $s = urandom(32);
    my $x = bytes2int(H($s . $self->I() . $self->P()));

    $self->s($s);
    $self->v(Math::BigInt->new(g())->copy->bmodpow($x->bstr, N()));

    return $self->state('init');
}

sub cbc_decrypt {
    my ($self, $data) = @_;

    my $blocksize = $self->cbc_blocksize();

    die('length($data) % $blocksize != 0') unless (length($data) % $blocksize == 0);

    my $IV = substr($data, 0, $blocksize);
    $data = substr($data, $blocksize);

    my $plaintext = '';

    foreach (@{[ 0 .. (length($data) / $blocksize) - 1 ]}) {
        my $temp = $self->cipher->decrypt(substr($data, 0, $blocksize));
        my $temp2 = xorstring($temp, $IV, $blocksize);
        $plaintext .= $temp2;
        $IV = substr($data, 0, $blocksize);
        $data = substr($data, $blocksize);
    }

    return $plaintext;
}

sub cbc_encrypt {
    my ($self, $data) = @_;

    my $blocksize = $self->cbc_blocksize();

    die('length($data) % $blocksize != 0') unless (length($data) % $blocksize == 0);

    my $IV = urandom($blocksize);
    die('len(IV) == blocksize') unless (length($IV) == $blocksize);

    my $ciphertext = $IV;

    foreach (@{[ 0 .. (length($data) / $blocksize) - 1 ]}) {
        my $xored = xorstring($data, $IV, $blocksize);
        my $enc = $self->cipher->encrypt($xored);

        $ciphertext .= $enc;
        $IV = $enc;
        $data = substr($data, $blocksize);
    }

    die('len(ciphertext) % blocksize == 0') unless (length($ciphertext) % $blocksize == 0);

    return $ciphertext;
}

sub decrypt_message {
    my ($self, $msg) = @_;

    substr($msg, 0, 1, '');

    my $raw = MIME::Base64::decode_base64($msg);

    my $cmac = substr($raw, 0, 16);
    my $ctext = substr($raw, 16);

    if ($cmac ne hmac_sha256_128($self->mac_key, $ctext)) {
        $self->error('decrypt_message: wrong mac!');
        $self->state('error');
    }

    my $padded = $self->cbc_decrypt($ctext);

    my $plain = $padded;
    $plain =~ s/^\x00*//;
    $plain =~ s/\x00*$//;

    unless (substr($plain, 0, 1) eq 'M') {
        $self->error('decrypt_message: not M');
        $self->state->('error');
    }

    my $usernamelen = ord(substr($plain, 1, 2));
    my $username = substr($plain, 2, $usernamelen);

    my $msg = substr($plain, 4 + 2 + $usernamelen);

    if ($msg =~ /^\xffKEY/) {

        my $new = substr($msg, 4);

        if (length($new) != (32 + 32)) {
            $self->error('decrypt_message: length($new) != 32 + 32 ; length is ' . length($new));
            $self->state('error');
        }

        $self->debug_cb->('decrypt_message: rekeying');

        $self->session_key(substr($new, 0, 32));
        $self->mac_key(substr($new, 32, 32));
        $self->cipher(Crypt::OpenSSL::AES->new($self->session_key));

        return;
    }

    $self->debug_cb->("decrypt_message: from $username ; msg $msg");

    return $msg;
}

sub encrypt_message {
    my ($self, $who, $msg) = @_;

    my $times = pack('L>', int(time()));

    # info = len(username) || username || timestamp
    my $infos = chr(length($who)) . $who . $times;

    # ctext = IV || AES-CBC(sessionkey, IV, "M" || info || plaintext)
    my $ctext = $self->cbc_encrypt(padto('M' . $infos . $msg, 16));

    # cmac = HM(mackey, ctext)
    my $cmac = hmac_sha256_128($self->mac_key, $ctext);

    # ircmessage = "*" || Base64(cmac || ctext)
    return '*' . MIME::Base64::encode_base64($cmac . $ctext, '');
}

no Moose;

__PACKAGE__->meta->make_immutable;
1;

=head1 DESCRIPTION

L<Algorithm::IRCSRP2> implements the IRCSRP version 2 algorithm as specified in
L<http://www.bjrn.se/ircsrp/ircsrp.2.0.txt>.

From the specification:

   IRCSRP is based on the SRP-6 protocol [3] for password-authenticated key
   agreement. While SRP was originally designed for establishing a secure,
   authenticated channel between a user and a host, it can be adapted for group
   communcations, as described in this document.

=head1 CURRENT CAVEATS

=over

=item * Only Alice is implemented

=back

=head1 SYNOPSIS

See L<https://gitorious.org/ircsrp/ircsrp> for a working version used in Pidgin.

=head1 SEE ALSO

=over

=item * L<http://www.bjrn.se/ircsrp/>

=back
