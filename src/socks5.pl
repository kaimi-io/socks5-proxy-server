#!/usr/bin/perl
#В коде использованы части rdss (.Slip) и sss (hm2k)
use strict;
use IO::Select;
use Socket;
use threads;
use threads::shared;

if(scalar @ARGV < 2)
{
	die "Usage: serv.pl host port login pass\n";
}

my ($host, $port, $login, $passw) = @ARGV;

my %config = (thr_init => 10, thr_min => 2, thr_max => 20, conn_limit => SOMAXCONN);

$| = 1;

my %status : shared;
my $accept : shared;

my $sock_addr = sockaddr_in $port, inet_aton($host) or die $!;
socket my $socket, PF_INET, SOCK_STREAM, getprotobyname('tcp') or die $!;
bind $socket, $sock_addr or die $!;
listen $socket, $config{'conn_limit'} or die $!;


my $sel = IO::Select->new($socket);

print "Starting...\n";

replenish($config{'thr_init'});

while(1)
{
	lock %status;
	cond_wait %status;
	
	my @free = sort {$a <=> $b} grep {$status{$_} eq 'free'} keys %status;
	
	if(scalar @free < $config{'thr_min'})
	{
		replenish($#free - $config{'thr_min'});
	}
	elsif(scalar @free > $config{'thr_max'})
	{
		my @kill = @free[0..$#free - $config{'thr_max'}];
		status($_ => 'kill') for @kill;
	}
}

status($_ => 'kill') for keys %status;

sub main
{
	my $sock = shift;
	my $loop = 50;
	
	my $tid = threads->tid;
	my $conn;
	
	threads->self->detach;
	status($tid, 'free');
	
	while(status($tid) ne 'kill' && $loop > 0)
	{
		next unless $sel->can_read(.1);
		{
			lock $accept;
			next unless accept $conn, $sock;
		}
		$loop--;
		status($tid => 'work');
		new_client($conn);
		close $conn;
		status($tid => 'free');
	}
	
	status($tid, 'kill');
}

sub status
{
	my ($tid, $state) = @_;
	lock %status;
	
	return $status{$tid} unless $state;
	if($state)
	{
		$status{$tid} = $state unless defined $status{$tid} and $status{$tid} eq 'kill';
	}
	else
	{
		delete $status{$tid};
	}
	
	cond_broadcast %status;
}

sub replenish
{
	threads->create(\&main, $socket) for 1..$_[0];
}

sub new_client
{
	my $sock = shift;
	
	sysread $sock, my $buf, 2;
	
	my ($ver, $auth_num) = unpack('H2H2', $buf);
	#Версия протокола
	return unless $ver eq '05';
	sysread $sock, $buf, $auth_num;
	
	my $ok = 0;
	#Перечисление методов авторизации
	for(my ($mode, $i) = (0, 0); $i < $auth_num; $mode = ord substr $buf, ++$i, 1)
	{
		#0 - Без авторизации; 2 - Username/Password
		if($mode == 0 && !$login)
		{
			syswrite $sock, "\x05\x00";
			$ok++;
			last;
		}
		elsif($mode == 2 && $login)
		{
			return unless socks_auth($sock);
			$ok++;
			last;
		}
	}
	#Подходящие методы есть
	if($ok)
	{
		sysread $sock, $buf, 3;
		my ($ver, $cmd, $r) = unpack 'H2H2H2', $buf;
		
		if($ver eq '05' && $r eq '00')
		{
			my ($client_host, $client_host_raw, $client_port, $client_port_raw) = get_conn_info($sock);
			return unless ($client_host || $client_port);
			
			syswrite $sock, "\x05\x00\x00".$client_host_raw.$client_port_raw;
			handle_client($sock, $client_host, $client_port, $cmd);
		}
	}
	else
	{
		syswrite $sock, "\x05\xFF";
	}
}

sub socks_auth
{
	my $sock = shift;
	
	syswrite $sock, "\x05\x02";
	sysread $sock, my $buf, 1;
	
	if(ord $buf == 1)
	{
		#username length : username : password length : password
		sysread $sock, $buf, 1;
		sysread $sock, my $s_login, ord($buf);
		sysread $sock, $buf, 1;
		sysread $sock, my $s_passw, ord($buf);
		
		#0x00 = success; any other value = failure
		if($login eq $s_login && $passw eq $s_passw)
		{
			syswrite $sock, "\x05\x00";
			return 1;
		}
		else
		{
			syswrite $sock, "\x05\x01";
		}
	}
	
	return 0;
}

sub handle_client
{
	my ($sock, $host, $port, $cmd) = @_;
	
	#0x01 = establish a TCP/IP stream connection
	if($cmd == 1)
	{
		my $sock_addr = sockaddr_in $port, inet_aton($host) or return;
		socket my $target, PF_INET, SOCK_STREAM, getprotobyname('tcp') or return;
		connect $target, $sock_addr or return;
		
		while($sock || $target)
		{
			my ($rin, $cbuf, $tbuf, $rout, $eout) = ('', '', '', '', '');
			vec($rin, fileno($sock), 1) = 1 if $sock;
			vec($rin, fileno($target), 1) = 1 if $target;
			select($rout = $rin, undef, $eout = $rin, 120);
			return if(!$rout && !$eout);
			
			if($sock && (vec($eout, fileno($sock), 1) || vec($rout, fileno($sock), 1)))
			{
				my $res = sysread $sock, $tbuf, 1024;
				return if(!defined $res || !$res);
			}
			if($target && (vec($eout, fileno($target), 1) || vec($rout, fileno($target), 1)))
			{
				my $res = sysread $target, $cbuf, 1024;
				return if(!defined $res || !$res);
			}
			while(my $len = length($tbuf))
			{
				my $r = syswrite $target, $tbuf, $len;
				return if(!defined $r || $r <= 0);
				$tbuf = substr($tbuf, $r);
			}
			while(my $len = length($cbuf))
			{
				my $r = syswrite $sock, $cbuf, $len;
				return if(!defined $r || $r <= 0);
				$cbuf = substr($cbuf, $r);
			}
		}
	}
}

sub get_conn_info
{
	my $sock = shift;
	
	my ($host, $raw_host) = ('', '');
	sysread $sock, my $buf, 1;
	($raw_host, $buf) = ($buf, ord $buf);
	#0x01 = IPv4 address; 0x03 = Domain name
	if($buf == 1)
	{
		#4 bytes for IPv4 address
		sysread $sock, $buf, 4;
		$raw_host .= $buf;
		$host = join '.', map(ord, split //, $buf);
	}
	elsif($buf == 3)
	{
		#1 byte of name length followed by the name for Domain name
		sysread $sock, $buf, 1;
		sysread $sock, $host, ord($buf);
		$raw_host .= $host;
	}
	
	#port number in a network byte order, 2 bytes
	my ($port, $raw_port) = ('', '');
	sysread $sock, $raw_port, 2;
	$port = ord(substr($raw_port, 0, 1)) << 8 | ord(substr($raw_port, 1, 1));
	
	return $host, $raw_host, $port, $raw_port;
}
