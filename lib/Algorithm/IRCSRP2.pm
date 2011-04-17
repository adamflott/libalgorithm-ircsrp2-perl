package Algorithm::IRCSRP2;

# ABSTRACT: IRCSRP is an IRC channel encryption algorithm

use Moose;

use Moose::Util::TypeConstraints qw(enum);

# core
use Data::Dumper;
use Digest::SHA;
use MIME::Base64;
use Math::BigInt only => 'GMP,Pari';
use Scalar::Util qw(blessed);

# CPAN
use Crypt::OpenSSL::AES;

foreach my $k (qw(I x a A b B S u K1 K2 M1 M2 P s v)) {
    has $k => (
        'isa'     => 'Maybe[Str|Object]',
        'is'      => 'rw',
        'default' => undef,
        'trigger' => sub {
            my ($self, $new, $old) = @_;

            my $str = "Changing IRCSRP exchange $k from %s to %s";

            my ($oldstr, $newstr);

            my $formatstr = sub {
                my ($string) = @_;

                my $retstr;

                if (blessed($string)) {
                    $retstr = (blessed($string) eq 'Math::BigInt') ? $string->bstr : $retstr;
                }
                elsif (!defined($string)) {
                    $retstr = 'undef';
                }
                else {
                    if ($string =~ /[[:^ascii:]]/) {
                        $retstr = Algorithm::IRCSRP2::bytes2int($string);
                    }
                    else {
                        $retstr = $string;
                    }
                }
                return $retstr;
            };

            $self->debug_cb->(sprintf($str, $formatstr->($old), $formatstr->($new)));
        }
    );
}

has 'cipher' => (
    'isa' => 'Crypt::OpenSSL::AES',
    'is'  => 'rw',
);

has 'session_key' => (
    'isa' => 'Str',
    'is'  => 'rw',
);

has 'mac_key' => (
    'isa' => 'Str',
    'is'  => 'rw',
);

has 'error' => (
    'isa' => 'Str',
    'is'  => 'rw',
);

foreach my $p (qw(prefs_am_i_dave prefs_account prefs_channel prefs_dave_nick prefs_user prefs_password)) {
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

has 'am_i_dave' => (
    'isa'     => 'Bool',
    'is'      => 'ro',
    'default' => 0
);

has 'cbc_blocksize' => (
    'isa'     => 'Int',
    'is'      => 'ro',
    'default' => 16
);

# Alice's states: null -> init -> srpa0 | error -> srpa1 | error | null -> srpa2 | error | null -> authenticated | null
has 'state' => (
    'isa'     => enum([qw(null error init srpa0 srpa1 srpa2 srpa3 authenticated)]),
    'is'      => 'rw',
    'default' => 'null',
    'trigger' => sub {
        my ($self, $new, $old) = @_;

        $self->debug_cb->("State change $old -> $new");

        if ($new eq 'error') {
            $self->debug_cb->('Fatal error: ', $self->error);
        }
    }
);

# -------- constants --------
sub H { Digest::SHA::sha256(@_) }

sub g { 2 }

sub N {
    my @modp14 = qw(
      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF);

    my $s = join('', @modp14);

    $s =~ s/\s*//g;
    $s =~ s/\n//g;

    return Math::BigInt->new('0x' . $s)->bstr;
}

# -------- utilities --------
sub urandom {
    my ($amount) = @_;

    my $s;
    open(my $r, '<', '/dev/urandom') or die $!;
    read($r, $s, $amount) or die $!;

    return $s;
}

sub randint {
    my ($a, $b) = @_;
    my $c    = $b->copy;
    my $bits = (int($c->blog(2)) + 1) / 8;

    my $candidate = 0;

    while (1) {
        $candidate = bytes2int(urandom($bits));
        if ($a <= $candidate && $candidate <= $b) {
            last;
        }
    }
    die "a <= candidate <= b" unless ($a <= $candidate && $candidate <= $b);

    return $candidate->bstr;
}

sub gen_a {
    my $n = Math::BigInt::->new(N());
    $n->bsub(1);
    return randint(2, $n);
}

sub int2bytes {
    my ($n) = @_;

    $n = $n->copy;

    if ($n == 0) { return 0x00 }

    my $b = '';

    while ($n) {
        $b = chr($n->copy->bmod(256)->bstr) . $b;
        $n->bdiv(256);
    }

    return $b;
}

sub bytes2int {
    my ($bytes) = @_;

    my @bs = split('', $bytes);

    my $n = Math::BigInt->new(0);

    foreach my $b (@bs) {
        $n->bmul(256);
        $n->badd(ord($b));
    }

    return $n;
}

sub xorstring {
    my ($a, $b, $blocksize) = @_;

    my $xored = '';

    my @as = split('', $a);
    my @bs = split('', $b);

    foreach my $i (@{[ 0 .. $blocksize - 1 ]}) {
        $xored .= chr(ord($as[$i]) ^ ord($bs[$i]));
    }

    return $xored;
}

sub padto {
    my ($msg, $length) = @_;

    my $L = length($msg);

    if ($L % $length) {
        $msg .= (chr(0) x ($length - $L % $length));
    }

    die('lenth($msg) % $length != 0') unless ((length($msg) % $length) == 0);

    return $msg;
}

sub hmac_sha256_128 {
    my ($key, $data) = @_;

    my $str = Digest::SHA::hmac_sha256($data, $key);
    $str = substr($str, 0, 16);

    return $str;
}

# -------- methods --------
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

sub ircsrp_generate {
    my ($self) = @_;

    my $s = urandom(32);

    my $x = bytes2int(H($s . $self->I() . $self->P()));

    $self->s($s);
    $self->v(Math::BigInt->new(g())->copy->bmodpow($x->bstr, N()));
}

sub verify_srpa1 {
    my ($self, $msg) = @_;

    my $decoded = MIME::Base64::decode_base64($msg);

    my $s = substr($decoded, 0, 32, '');
    $self->s($s);

    my $B = $self->B(bytes2int($decoded));

    if ($B->copy->bmod(N()) != 0) {
        $self->state('srpa1');

        return $self->srpa2();
    }
    else {
        $self->error('srpa1');
        $self->state('error');
    }
}

sub verify_srpa3 {
    my ($self, $msg) = @_;

    my $cipher = MIME::Base64::decode_base64($msg);

    my $cmac = substr($cipher, 0, 16);

    if (hmac_sha256_128($self->K2(), substr($cipher, 16)) ne $cmac) {
        $self->error('incorrect mac');
        $self->state('error');
    }

    $self->state('srpa3');

    $self->cipher(Crypt::OpenSSL::AES->new($self->K1()));

    my $plain = $self->cbc_decrypt(substr($cipher, 16));

    my $sessionkey = substr($plain, 0,  32);
    my $mackey     = substr($plain, 32, 32);
    my $M2         = substr($plain, 64, 32);

    $self->debug_cb->('sessionkey ' . bytes2int($sessionkey));
    $self->debug_cb->('mackey ' . bytes2int($mackey));

    my $M2ver = H(join('', int2bytes($self->A()), $self->M1(), int2bytes($self->S())));

    $self->debug_cb->('M2 ' . bytes2int($M2));
    $self->debug_cb->('M2ver ' . bytes2int($M2ver));

    if ($M2 ne $M2ver) {
        $self->error('M2 != M2ver');
        $self->state('error');
    }

    $self->session_key($sessionkey);
    $self->cipher(Crypt::OpenSSL::AES->new($sessionkey));
    $self->mac_key($mackey);

    $self->state('authenticated');
}

sub srpa0 {
    my ($self) = @_;

    return '+srpa0 ' . $self->prefs_user;
}

sub srpa2 {
    my ($self) = @_;

    # a = random integer with 1 < a < N.
    my $a = Math::BigInt->new(gen_a());
    $self->a($a);

    # A = g^a (mod N)
    my $A = Math::BigInt->new(g());
    $A->bmodpow($a->bstr, N());
    $self->A($A);

    # x = H(s || I || P)
    my $x = bytes2int(H($self->s() . $self->I() . $self->P()));
    $self->x($x);

    # u = H(A || B)
    my $u = bytes2int(H(int2bytes($A) . int2bytes($self->B())));
    $self->u($u);

    # S = (B - 3g^x)^(a + ux) (mod N)
    my $t = Math::BigInt->new(g());
    $t->bmodpow($x->bstr, N());
    $t->bmul(3);

    my $q = $self->B()->copy;
    $q->bsub($t);

    $t = $q->copy;

    my $t2 = $u->copy;
    $t2->bmul($x->bstr);
    $t2->badd($a->bstr);
    $t2->bmod(N());

    my $S = $t->copy;
    $S->bmodpow($t2->bstr, N());
    $self->S($S);

    # K1 = H(S || "enc")
    my $K1 = Digest::SHA::sha256(int2bytes($S) . 'enc');
    $self->K1($K1);

    # K2 = H(S || "auth")
    my $K2 = Digest::SHA::sha256(int2bytes($S) . 'auth');
    $self->K2($K2);

    # M1 = H(A || B || S)
    my $M1 = H(int2bytes($A) . int2bytes($self->B()) . int2bytes($S));
    $self->M1($M1);

    # ircmessage = "+srpa2 " || Base64(M1 || IntAsBytes(A))
    my $msg = MIME::Base64::encode_base64($M1 . int2bytes($A), '');

    $self->state('srpa2');

    return '+srpa2 ' . $msg;
}

sub decrypt_message {
    my ($self, $msg) = @_;

    substr($msg, 0, 1, '');

    my $raw = MIME::Base64::decode_base64($msg);

    my $cmac = substr($raw, 0, 16);
    my $ctext = substr($raw, 16);

    if ($cmac ne hmac_sha256_128($self->mac_key, $ctext)) {
        $self->debug_cb->('error', 'wrong mac!');
        die;
    }

    my $padded = $self->cbc_decrypt($ctext);

    my $plain = $padded;
    $plain =~ s/^chr(0)*//;

    unless (substr($plain, 0, 1) eq 'M') {
        $self->debug_cb->('error', 'not M');
    }

    my $usernamelen = ord(substr($plain, 1, 2));

    return substr($plain, 4 + 2 + $usernamelen);
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

1;
