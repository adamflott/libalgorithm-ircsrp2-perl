package Algorithm::IRCSRP2::Dave;

# ABSTRACT: Dave interface

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

has '+am_i_dave' => ('default' => 1, 'is' => 'ro');

# Dave's states: TODO
has 'state' => (
    'isa'     => enum([qw(null error init srpa0 srpa1 srpa2 srpa3 authenticated)]),
    'is'      => 'rw',
    'default' => 'null',
    'trigger' => sub {
        my ($self, $new, $old) = @_;

        $self->debug_cb->("State change $old -> $new");

        if ($new eq 'error') {
            $self->debug_cb->('Fatal error: ', $self->error);
            die($self->error);
        }
    }
);

has 'users' => (
    'is'    => 'rw',
    'traits'  => ['Hash'],
    'isa'     => 'HashRef[Algorithm::IRCSRP2::Alice]',
    'default' => sub { {} },
    'handles' => {
        'set_user'     => 'set',
        'get_user'     => 'get',
        'has_no_users' => 'is_empty',
        'num_users'    => 'count',
        'delete_user'  => 'delete',
        'user_pairs'   => 'kv',
    },
);

sub verify_srpa0 {
    my ($self, $sender, $msg) = @_;

    $msg =~ s/^\+srpa0 //;

    my $user = Algorithm::IRCSRP2::Alice->new('nickname' => $sender,
                                              'debug_cb' => \&{$self->_orig_debug_cb});

    $user->I($msg);
    $user->P($self->P);
    $user->init;

    my $v = Math::BigInt->new($user->v);

    my $B = Math::BigInt->new(g());
    $B->bmodpow($self->b, N());
    $B->badd($v->copy->bmul(3));
    $B->bmod(N());

    $user->b(Math::BigInt->new(gen_a()));
    $user->B($B);

    $self->set_user($sender => $user);

    return '+srpa1 ' . MIME::Base64::encode_base64($user->s . int2bytes($B));
}

sub verify_srpa2 {
    my ($self, $sender, $msg) = @_;

    my $decoded = MIME::Base64::decode_base64($msg);

    $decoded =~ s/^\+srpa2 //;

    my $user = $self->get_user($sender);

    unless ($user) {
        $self->error("could not find user $sender");
        $self->state('error');
    }

    my $M1 = substr($decoded, 0, 32);
    my $A = bytes2int(substr($decoded, 32));

    if ($A->bmod(N()) == 0) {
        $self->error('dave: A % N == 0');
        $self->state('error');
    }

    my $u = bytes2int(H(int2bytes($A) . int2bytes($user->B)));

    my $S = Math::BigInt->new($user->v->bstr);
    $S->bmodpow($u->bstr, N());
    $S->bmul($A->bstr);

    my $S2 = Math::BigInt->new($S->bstr);
    $S2->bmodpow($user->b->bstr, N());
    $self->S($S2);

    my $K1 = Digest::SHA::sha256(int2bytes($S2) . 'enc');
    $self->K1($K1);

    my $K2 = Digest::SHA::sha256(int2bytes($S) . 'auth');
    $self->K2($K2);

    my $M2 = H(int2bytes($A) . $M1 . int2bytes($S2));
    $self->M2($M2);

    my $M1ver = H(int2bytes($A) . int2bytes($user->B) . int2bytes($S2));

    if ($M1 ne $M1ver) {
        $self->error('M1 != M1ver : ' . bytes2int($M1) . ' ne ' . bytes2int($M1ver));
        $self->state('error');
    }

    my $aes = Crypt::OpenSSL::AES->new($K1);
    $self->cipher($aes);

    #    del ctx.users.others[$sender]

    my $csession = $self->cbc_encrypt($self->session_key . $self->mac_key . $M2);

    my $cmac = hmac_sha256_128($K2, $csession);

    return '+srpa3 ' . MIME::Base64::encode_base64($cmac . $csession);
}

no Moose::Util::TypeConstraints;
no Moose;

__PACKAGE__->meta->make_immutable;

1;
