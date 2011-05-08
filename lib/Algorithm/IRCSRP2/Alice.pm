package Algorithm::IRCSRP2::Alice;

# ABSTRACT: Alice interface

use Moose;

extends 'Algorithm::IRCSRP2';

with 'Algorithm::IRCSRP2::Exchange';

# core
use MIME::Base64;
use Digest::SHA;

# CPAN
use Crypt::OpenSSL::AES;
use Moose::Util::TypeConstraints qw(enum);

# local
use Algorithm::IRCSRP2::Utils qw(:all);

has '+am_i_dave' => ('default' => 0, 'is' => 'ro');

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

sub srpa0 {
    my ($self) = @_;

    $self->state('srpa0');

    return '+srpa0 ' . $self->I();
}

sub verify_srpa1 {
    my ($self, $msg) = @_;

    $msg =~ s/^\+srpa1 //;

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
        return 0;
    }
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
    my $x = bytes2int(H($self->s . $self->I . $self->P));
    $self->x($x);

    # u = H(A || B)
    my $u = bytes2int(H(int2bytes($A) . int2bytes($self->B)));
    $self->u($u);

    # S = (B - 3g^x)^(a + ux) (mod N)
    my $t = Math::BigInt->new(g());
    $t->bmodpow($x->bstr, N());
    $t->bmul(3);

    my $q = $self->B->copy;
    $q->bsub($t);

    $t = $q->copy;

    my $t2 = $u->copy;
    $t2->bmul($x->bstr);
    $t2->badd($a->bstr);
    $t2->bmod(N());

    my $S = $t->copy;

    $S->bmodpow($t2->bstr, N());
    $self->debug_cb->('h' x 20 . $S->bstr);
    $self->S($S);

    # K1 = H(S || "enc")
    my $K1 = Digest::SHA::sha256(int2bytes($S) . 'enc');
    $self->K1($K1);

    # K2 = H(S || "auth")
    my $K2 = Digest::SHA::sha256(int2bytes($S) . 'auth');
    $self->K2($K2);

    # M1 = H(A || B || S)
    my $M1 = H(int2bytes($A) . int2bytes($self->B) . int2bytes($S));
    $self->M1($M1);

    # ircmessage = "+srpa2 " || Base64(M1 || IntAsBytes(A))
    my $msg = MIME::Base64::encode_base64($M1 . int2bytes($A), '');

    $self->state('srpa2');

    return '+srpa2 ' . $msg;
}

sub verify_srpa3 {
    my ($self, $msg) = @_;

    $msg =~ s/^\+srpa3 //;

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

    my $M2ver = H(join('', int2bytes($self->A), $self->M1, int2bytes($self->S)));

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

    return 1;
}

no Moose::Util::TypeConstraints;
no Moose;

__PACKAGE__->meta->make_immutable;

1;
