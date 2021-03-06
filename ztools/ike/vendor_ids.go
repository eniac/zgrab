package ike

import (
	"fmt"
	"regexp"
	"strings"
)

type vendorIdTuple struct {
	vendorIdPattern    *regexp.Regexp
	implementationName string
}

var vendorIdTable []*vendorIdTuple

func lookupVendorId(id []byte) string {
	idStr := []byte(fmt.Sprintf("%02x", id))
	for _, tuple := range vendorIdTable {
		if tuple.vendorIdPattern.Match(idStr) {
			return tuple.implementationName
		}
	}
	return ""
}

func init() {
	lines := strings.Split(vendorIds, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		split := strings.Split(line, "\t")
		if len(split) != 2 {
			continue
		}
		tuple := new(vendorIdTuple)
		tuple.implementationName = split[0]
		tuple.vendorIdPattern = regexp.MustCompilePOSIX(split[1])
		vendorIdTable = append(vendorIdTable, tuple)
	}
}

var vendorIds = `
# The IKE Scanner (ike-scan) is Copyright (C) 2003-2013 Roy Hills,
# NTA Monitor Ltd.
#
# This file is part of ike-scan.
#
# ike-scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ike-scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ike-scan.  If not, see <http://www.gnu.org/licenses/>.
#
# ike-vendor-ids -- File containing known Vendor IDs for ike-scan
#
# Author: Roy Hills <Roy.Hills@nta-monitor.com>
#
# Format:
# Implementation_Name<Tab>Vendor_ID_Pattern
#
# The Vendor_ID_Pattern should be specified as a Posix extended regular
# expression that will match the hex value of the Vendor ID.  The Posix regular
# expression routines "regcomp" and "regexec" are used to compile and
# match the patterns.
#
# The hex value of the Vendor ID can only contain the characters [0-9a-f].
# The regular expression match is case insensitive so you can use either
# upper or lower case letters [A-F] in the pattern, although I recommend that
# you use only lower-case for consistency.
#
# The pattern is not anchored by default.  If you want to match from the
# beginning of the vendor ID hex value (which is normally the case), you
# should start your pattern with "^" to anchor it at the beginning of the hex
# value.  If you don't want to allow any extra trailing data, you should end
# the pattern with "$" to anchor it at the end of the hex value.
#
# Each entry must be on one line.  A line can be up to 254 characters long.
# To allow for longer lines, adjust the MAXLINE macro in ike-scan.h
#
# Lines beginning with '#' and blank lines are ignored.
#
# The input format is quite strict.  In particular, the separator between
# the implementation name and the VendorID pattern must be a single TAB and
# not a space.
#
# If you have problems adding entries, run ike-scan as:
# ike-scan -v -v -v <any-target>
# Which will dump the VendorID pattern table.
#
# There are examples and analysis of vendor ids returned by various
# implementations on the ike-scan wiki at
# http://www.nta-monitor.com/wiki/index.php/Ike-scan_Documentation
#
# You are encouraged to submit comments, improvements or suggestions
# at the github repository https://github.com/royhills/ike-scan
#

# Microsoft/Cisco IPsec implementation for Win-2000 and above.
# The first 16 bytes are the MD5 hash of "MS NT5 ISAKMPOAKLEY"
# The next four bytes appear to be a version number in big endian format
# The observed version numbers are:
#
# 2	Windows 2000
# 3	Windows XP SP1
# 4	Windows 2003 and Windows XP SP2
# 5	Windows Vista (tested against Beta 2 build 5384) and 2008 server
#	http://msdn.microsoft.com/en-us/library/cc233476.aspx

Windows-2000	^1e2b516905991c7d7c96fcbfb587e46100000002
Windows-XP-SP1	^1e2b516905991c7d7c96fcbfb587e46100000003
Windows-2003-or-XP-SP2	^1e2b516905991c7d7c96fcbfb587e46100000004
Windows-Vista	^1e2b516905991c7d7c96fcbfb587e46100000005
Windows-2008	^1e2b516905991c7d7c96fcbfb587e46100000006
Windows-7		^1e2b516905991c7d7c96fcbfb587e46100000007
Windows-2008-R2	^1e2b516905991c7d7c96fcbfb587e46100000008
Windows-8		^1e2b516905991c7d7c96fcbfb587e46100000009
Windows-2012	^1e2b516905991c7d7c96fcbfb587e46100000010
Windows			^1e2b516905991c7d7c96fcbfb587e46.........

# Checkpoint Firewall-1/VPN-1
#
# Firewall-1 v4.0 didn't use Vendor IDs.  v3.0 and below didn't support IPsec.
#
# This is a 40-byte Vendor ID, which consists of the following fields:
#
# Bytes		Description
#  1-20		Checkpoint VID (Probably an SHA1 hash of something)
# 21-24		Product (1=Firewall-1, 2=SecuRemote/SecureClient)
# 25-28		Encoded Version number
# 29-32		Timestamp (NGX only; always zero in 4.1 or NG)
# 33-36		Reserved
# 37-40		Features
#
# The Checkpoint VID is "f4ed19e0c114eb516faaac0ee37daf2807b4381f".  I suspect
# that this is an SHA1 hash of something, but I don't know what the input text
# is.
#
# The Product is either 1 (0x00000001) for Firewall-1/VPN-1 or 2 (0x00000002)
# for SecuRemote/SecureClient (Checkpoint's VPN client).
#
# The encoded version number is described in the URL below.
#
# The timestamp field contains the Firewall's date and time encoded as seconds
# since 1st Jan 1970 (standard Unix epoch).  Only NGX fills this in; it is
# always zero on 4.1 and NG.
#
# The first byte of the features field contains the number of bits used.  This
# is normally 0x18 (24).  The remaining three bytes (24 bits) are feature
# flags.
#
# Firewall-1 4.1 and NG only returns a Vendor ID if you send a Vendor ID
# payload starting with the Checkpoint VID. Firewall-1 NGX always returns
# a Vendor ID, regardless of whether the client sends the Checkpoint VID
# or not.
#
# See http://www.nta-monitor.com/news/checkpoint2004/index.htm for full details
#
Firewall-1 4.1 Base	^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000020000000000000000........
Firewall-1 4.1 SP1	^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000030000000000000000........
Firewall-1 4.1 SP2-SP6	^f4ed19e0c114eb516faaac0ee37daf2807b4381f0000000100000fa20000000000000000........
Firewall-1 NG Base	^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013880000000000000000........
Firewall-1 NG FP1	^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013890000000000000000........
Firewall-1 NG FP2	^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138a0000000000000000........
Firewall-1 NG FP3	^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138b0000000000000000........
Firewall-1 NG AI R54	^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138c0000000000000000........
Firewall-1 NG AI R55	^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d0000000000000000........
Firewall-1 NGX or later	^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d........00000000........
Firewall-1 Unknown Vsn	^f4ed19e0c114eb516faaac0ee37daf2807b4381f

# Dead Peer Detection (DPD), detailed in RFC 3706.
# This is a truncated MD5 hash of "CISCO-DEAD-PEER-DETECTION"
# The last 2 bytes (4 hex chars) are major & minor version.
# The current version, and the only one that has been observed, is 1.0.
# Thanks to Hakan Olsson for clarifing this.
Dead Peer Detection v1.0	^afcad71368a1f1c96b8696fc77570100
Dead Peer Detection	^afcad71368a1f1c96b8696fc7757....

# XAUTH
# This is a truncated MD5 hash of "draft-ietf-ipsra-isakmp-xauth-06.txt"
# IPSRA = "IP Security Remote Access"
# Also known as "draft-beaulieu-ike-xauth-02.txt"
XAUTH	^09002689dfd6b712

# SSH Communications Security IPSEC Express
# These VIDs are MD5 hashes of the text
# "SSH Communications Security IPSEC Express version x.y.z" or
# "Ssh Communications Security IPSEC Express version x.y.z"
# Where x.y.z is the version, e.g. 1.1.0
SSH IPSEC Express 1.1.0	^fbf47614984031fa8e3bb6198089b223
SSH IPSEC Express 1.1.1	^1952dc91ac20f646fb01cf42a33aee30
SSH IPSEC Express 1.1.2	^e8bffa643e5c8f2cd10fda7370b6ebe5
SSH IPSEC Express 1.2.1	^c1111b2dee8cbc3d620573ec57aab9cb
SSH IPSEC Express 1.2.2	^09ec27bfbc09c75823cfecbffe565a2e
SSH IPSEC Express 2.0.0	^7f21a596e4e318f0b2f4944c2384cb84
SSH IPSEC Express 2.1.0	^2836d1fd2807bc9e5ae30786320451ec
SSH IPSEC Express 2.1.1	^a68de756a9c5229bae66498040951ad5
SSH IPSEC Express 2.1.2	^3f2372867e237c1cd8250a75559cae20
SSH IPSEC Express 3.0.0	^0e58d5774df602007d0b02443660f7eb
SSH IPSEC Express 3.0.1	^f5ce31ebc210f44350cf71265b57380f
SSH IPSEC Express 4.0.0	^f64260af2e2742daddd56987068a99a0
SSH IPSEC Express 4.0.1	^7a54d3bdb3b1e6d923892064be2d981c
SSH IPSEC Express 4.1.0	^9aa1f3b43472a45d5f506aeb260cf214
SSH IPSEC Express 4.1.1	^89f7b760d86b012acf263382394d962f
SSH IPSEC Express 4.2.0	^6880c7d026099114e486c55430e7abee
SSH IPSEC Express 5.0	^b037a21aceccb5570f602546f97bde8c
SSH IPSEC Express 5.0.0	^2b2dad97c4d140930053287f996850b0
SSH IPSEC Express 5.1.0	^45e17f3abe93944cb202910c59ef806b
SSH IPSEC Express 5.1.1	^5925859f7377ed7816d2fb81c01fa551

# Cisco Unity compliant peer. VID is the MD5 hash of "CISCO-UNITY" with
# the last two bytes replaced with 0x0100.
Cisco Unity	^12f5f28c457168a9702d9fe274cc0100

# Cisco VPN 3000 Concentrator (formerly Altega Networks)
# There are several models: 3005, 3015, 3020, 3030, 3060 and 3080, which are
# equivalent to the old Altiga C5, C15 Etc.
#
# The VPN 3000 client VID is the MD5 hash of "ALTIGA NETWORKS"
# The VPN 3000 concentrator VID is a truncated MD5 hash of "ALTIGA GATEWAY"
#
# I've seen this pattern with trailing 500306 and 500400.  I suspect that
# the last two bytes indicate the version number, e.g 0306 = 3.0.6.  However,
# I need more examples before I'm confident that this is the case, so for
# now I'm just including the generic pattern.
Cisco VPN Concentrator (3.0.0)	^1f07f70eaa6514d3b0fa96542a500300
Cisco VPN Concentrator (3.0.1)	^1f07f70eaa6514d3b0fa96542a500301
Cisco VPN Concentrator (3.0.5)	^1f07f70eaa6514d3b0fa96542a500305
Cisco VPN Concentrator (4.0.7)	^1f07f70eaa6514d3b0fa96542a500407
VPN-3000-client	^f6f7efc7f5aeb8cb158cb9d094ba69e7
Cisco VPN Concentrator	^1f07f70eaa6514d3b0fa96542a

# IKE Fragmentation.  VID is the MD5 hash of the text "FRAGMENTATION"
# I've seen extra bytes on the end of a fragmentation VID payload, e.g.
# c0000000 and 80000000.  I don't know what these represent.
IKE Fragmentation	^4048b7d56ebce88525e7de7f00d6c2d3

# Various IKE Internet drafts.  The VID payload is the MD5 hash of the
# implementation name given below.
draft-stenberg-ipsec-nat-traversal-01	^27bab5dc01ea0760ea4e3190ac27c0d0
draft-stenberg-ipsec-nat-traversal-02	^6105c422e76847e43f9684801292aecd
draft-huttunen-ipsec-esp-in-udp-00.txt	^6a7434c19d7e36348090a02334c9c805

# SafeNet SoftRemote VPN Client.
# Extra data has been observed at the end of this VID payload.
SafeNet SoftRemote 8.0.0	^47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310382e302e3020284275696c6420313029000000
SafeNet SoftRemote 9.0.1	^47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310392e302e3120284275696c6420313229000000
SafeNet SoftRemote	^47bbe7c993f1fc13b4e6d0db565c68e5

# HeartBeat Notify.
# VID is ASCII "HeartBeat_Notify"
# Extra data has been observed at the end of this VID payload.  It is
# suspected that this may be a version number.  E.g:
# 4865617274426561745f4e6f74696679386b0100
HeartBeat_Notify	^4865617274426561745f4e6f74696679
HeartBeat Notify	^486561727442656174204e6f74696679

# OpenPGP
OpenPGP	^4f70656e5047503130313731

# draft-huttunen-ipsec-esp-in-udp-01.txt
# VID is an MD5 hash of "ESPThruNAT"
ESPThruNAT	^50760f624c63e5c53eea386c685ca083

# SSH Sentinel.
# These VIDs are MD5 hashes of the implementation names given below.
SSH Sentinel	^054182a07c7ae206f9d2cf9d2432c482
SSH Sentinel 1.1	^b91623e693ca18a54c6a2778552305e8
SSH Sentinel 1.2	^5430888de01a31a6fa8f60224e449958
SSH Sentinel 1.3	^7ee5cb85f71ce259c94a5c731ee4e752
SSH Sentinel 1.4	^63d9a1a7009491b5a0a6fdeb2a8284f0
SSH Sentinel 1.4.1	^eb4b0d96276b4e220ad16221a7b2a5e6

# Timestep VID is ASCII "TIMESTEP" (54494d4553544550) followed by further
# ASCII characters which seem to indicate a version number.  e.g:
# 54494d455354455020312053475720313532302033313520322e303145303133
# which is "TIMESTEP 1 SGW 1520 315 2.01E013"
Timestep	^54494d4553544550

# VID is MD5 hash of "KAME/racoon"
KAME/racoon	^7003cbc1097dbe9c2600ba6983bc8b35

# Negotiation of NAT-Traversal in the IKE - previously IETF draft, now RFC.
# The VID is the MD5 hash of the implementation name given below.
# The trailing newline (\n) on one entry is explained in
# http://www.sandelman.ottawa.on.ca/ipsec/2002/04/msg00233.html
# Jan 2005: RFC released as RFC 3947 "Negotiation of NAT-Traversal in the IKE"
# VID is MD5 hash of "RFC 3947"
draft-ietf-ipsec-nat-t-ike	^4df37928e9fc4fd1b3262170d515c662
draft-ietf-ipsec-nat-t-ike-00	^4485152d18b6bbcd0be8a8469579ddcc
draft-ietf-ipsec-nat-t-ike-01	^16f6ca16e4a4066d83821a0f0aeaa862
draft-ietf-ipsec-nat-t-ike-02\n	^90cb80913ebb696e086381b5ec427b1f
draft-ietf-ipsec-nat-t-ike-02	^cd60464335df21f87cfdb2fc68b6a448
draft-ietf-ipsec-nat-t-ike-03	^7d9419a65310ca6f2c179d9215529d56
draft-ietf-ipsec-nat-t-ike-04	^9909b64eed937c6573de52ace952fa6b
draft-ietf-ipsec-nat-t-ike-05	^80d0bb3def54565ee84645d4c85ce3ee
draft-ietf-ipsec-nat-t-ike-06	^4d1e0e136deafa34c4f3ea9f02ec7285
draft-ietf-ipsec-nat-t-ike-07	^439b59f8ba676c4c7737ae22eab8f582
draft-ietf-ipsec-nat-t-ike-08	^8f8d83826d246b6fc7a8a6a428c11de8
draft-ietf-ipsec-nat-t-ike-09	^42ea5b6f898d9773a575df26e7dd19e1
Testing NAT-T RFC	^c40fee00d5d39ddb1fc762e09b7cfea7
RFC XXXX	^810fa565f8ab14369105d706fbd57279
RFC 3947 NAT-T	^4a131c81070358455c5728f20e95452f

# A GSS-API Authentication Method for IKE - draft-ietf-ipsec-isakmp-gss-auth
# This is used by Windows 2000 and later.  Specific Windows VIDs are in a
# separate section.
# Note that the MD5 hash for "A GSS-API ..." in draft version 07 is given as
# the hash of the string with a newline appended.  I think that this is an
# error, so I've added patterns both with and without the trailing newline.
MS NT5 ISAKMPOAKLEY	^1e2b516905991c7d7c96fcbfb587e461
A GSS-API Authentication Method for IKE	^ad2c0dd0b9c32083ccba25b8861ec455
A GSS-API Authentication Method for IKE\n	^b46d8914f3aaa3f2fedeb7c7db2943ca
GSSAPI	^621b04bb09882ac1e15935fefa24aeee
NLBS_PRESENT	^72872B95FCDA2EB708EFE322119B4971
MS-MamieExists	^214ca4faffa7f32d6748e5303395ae83
MS-Negotiation Discovery Capable	^fb1de3cdf341b7ea16b7e5be0855f120
IKE CGA version 1	^e3a5966a76379fe707228231e5ce8652

# Nortel Contivity VPN Router (was Bay Networks Enterprise Switch)
# The first 4 bytes are ASCII "BNES" (Bay Networks Enterprise Switch)
# The second 4 bytes appear to be a version number in big endian format.
# I've seen values 00000004, 00000005, 00000007, 00000009 and 0000000a in
# this position.
Nortel Contivity	^424e4553000000..

# Observed to be sent from SonicWall Firewalls
SonicWall-1	^5b362bc820f60001
SonicWall-3	^5b362bc820f60003
SonicWall-6	^5b362bc820f60006
SonicWall-7	^5b362bc820f60007
SonicWall-a	^404bf439522ca3f6
SonicWall-b	^da8e937880010000

# SSH QuickSec
# The VIDs are the MD5 hashes of "SSH Communications Security QuickSec x.y.z"
# Where x.y.z is the version number
SSH QuickSec 0.9.0	^37eba0c4136184e7daf8562a77060b4a
SSH QuickSec 1.1.0	^5d72925e55948a9661a7fc48fdec7ff9
SSH QuickSec 1.1.1	^777fbf4c5af6d1cdd4b895a05bf82594
SSH QuickSec 1.1.2	^2cdf08e712ede8a5978761267cd19b91
SSH QuickSec 1.1.3	^59e454a8c2cf02a34959121f1890bc87
SSH QuickSec 2.1.0	^8f9cc94e01248ecdf147594c284b213b

# VIDs are MD5 hash of:
# "IKE Challenge/Response for Authenticated Cryptographic Keys"
# "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)"
# both without and with trailing newline.
IKE Challenge-Response	^ba290499c24e84e53a1d83a05e5f00c9
IKE Challenge-Response-2	^0d33611a5d521b5e3c9c03d2fc107e12
IKE Challenge-Response Revised	^ad3251042cdc4652c9e0734ce5de4c7d
IKE Challenge-Response Revised-2	^13f11823f966fa91900f024ba66a86ba

# draft-krywaniuk-ipsec-antireplay-00.txt - Using Isakmp Message Ids for
# Replay Protection
#
#  "They may also be enabled in the short term by mutual exchange of the
#   vendor id 0x325df29a2319f2dd"
draft-krywaniuk-ipsec-antireplay-00	^325df29a2319f2dd

# draft-ietf-ipsec-heartbeats-00.txt - Using Isakmp Heartbeats for Dead Peer
# Detection
# The draft says that the VID is a truncated MD5 hash of
# "draft-ietf-krywaniuk-ipsec-heartbeats-00.txt"
# but it is not.
draft-ietf-ipsec-heartbeats-00	^8db7a41811221660

# MacOS X
# Unconfirmed, from StrongSwan vendor.c
MacOS 10.x-1	^4d6163204f53582031302e78
MacOS 10.x-2	^4df37928e9fc4fd1b3262170d515c662

# strongSwan
# VID is MD5 hash of "strongSwan x.y.z" where x.y.z is version number
# Originally obtained from strongSwan 4.0.5 pluto/vendor.c
strongSwan	^882fe56d6fd20dbc2251613b2ebe5beb
strongSwan 5.1.1	^9e10a0d4205edc6c90bd5381a53c2d2b
strongSwan 5.1.1rc1	^a55a90de781611f70cbbae7045a225fc
strongSwan 5.1.1dr4	^c90b020d043f1f050ba809e13dc8234e
strongSwan 5.1.1dr3	^06f2f1b82256dce62c07cb4f71604035
strongSwan 5.1.1dr2	^4f130d312ec92f50c02f2b0eb60d6ccc
strongSwan 5.1.1dr1	^1a45d3bda55646016e998ac1c5590e59
strongSwan 5.1.0	^b7d8e62184049fb21b088d4232d2549c
strongSwan 5.1.0rc1	^02c49867060173c665ebce2b8110c7f7
strongSwan 5.1.0dr2	^e069a583c5640257a8de2cf062461a4b
strongSwan 5.1.0dr1	^22982eab040be7a4cb4177da312f2f1c
strongSwan 5.0.4	^dc3afcdda0514da394b4b36f4cb1b9a7
strongSwan 5.0.3	^d398476a43b9d6c56c4045ffcc9fffb9
strongSwan 5.0.3rc1	^f2d4de999721c37fea51d4bcbc060120
strongSwan 5.0.3dr3	^f4d68a2fb63e4390a959baa5c4bc7598
strongSwan 5.0.3dr2	^7b3f3d21e4768e010fc7dd04ae369c61
strongSwan 5.0.3dr1	^ca7d77d20794391df5a3cb90fbf5b72e
strongSwan 5.0.2	^04d52cc5fd04aa971063b111917731d2
strongSwan 5.0.2rc1	^80b8f4380b18f24f03ce5745fc3db56b
strongSwan 5.0.2dr4	^a5f8ce0d6751c640e55bc41784f2e081
strongSwan 5.0.1	^75aa8f69de2e44500dae842be21f5491
strongSwan 5.0.0	^e154b11a96ee2b44d4954843cd3a40a3
strongSwan 4.6.4	^a87680d00cbb939871eb680d18d052e2
strongSwan 4.6.3	^984a7bfefb46489a5be74b64531c6753
strongSwan 4.6.2	^9c73b19f5f4181aa4b269dd004608811
strongSwan 4.6.1	^1d6cfa4d69d9d33c0b2244bf99de9b8b
strongSwan 4.6.0	^41ef2e2f7ec8b923c98d9fa9bb7a04a5
strongSwan 4.5.3	^75244ad8a5a0f48e7e3b7ad79dcab153
strongSwan 4.5.2	^b149d6161fb4c7c3805beeff042d08c0
strongSwan 4.5.1	^efe12e8533bbcf4e978ec874935e9972
strongSwan 4.5.0	^eff89e6f406f55292807c3b8f925884a
strongSwan 4.4.1	^aaa2e272c58de8f96e72c4c21ba7dd99
strongSwan 4.4.0	^a5ad81e15e1c68a1be277abfeee80d94
strongSwan 4.3.7	^02d7c3a0698ec33bb126b2baa70b9c2c
strongSwan 4.3.6	^882fe56d6fd20dbc2251613b2ebe5beb
strongSwan 4.3.5rc1	^117c406d20a29f56f0dfcb03d9fa835b
strongSwan 4.3.5	^de5c703801952d85f6b3ed33b33784b4
strongSwan 4.3.4	^e37e5d64a329a5cf1eeb8546c3b06018
strongSwan 4.3.3	^f9f093629308b24388d09c3f026de0a8
strongSwan 4.3.2	^d6263956ac790961a9c8409b393724bf
strongSwan 4.3.1	^20b1f62b240a52a849309183960cbb64
strongSwan 4.3.0	^9deb74e751f44c47905ed2fad93f9271
strongSwan 4.2.9	^488c08f57afc382112f7cb396f2d4f6c
strongSwan 4.2.8	^95569ee23ebb62eddedea353a575faf3
strongSwan 4.2.7	^4ddc7e1f6d6cd1ae9d5dcac58fa1fe9a
strongSwan 4.2.6	^a2782dd683b5edee3b777f897d2b867e
strongSwan 4.2.5	^af0a05e0bd37b0aba0135a194abb5b89
strongSwan 4.2.4	^cd5792d4b70f0299a6a1373de236d2ac
strongSwan 4.2.3	^2d1f406118fbd5d28474791ffa00488a
strongSwan 4.2.2	^2a517d0d23c37d08bce7c292a0217b39
strongSwan 4.2.1	^bab253f4cb10a8108a7c927c56c87886
strongSwan 4.2.0	^9f68901325a972894335302a9531ab9f
strongSwan 4.1.11	^b7bd9f2f978e3259a7aa9f7a1396ad6c
strongSwan 4.1.10	^bf3a89ae5bef8e72d44dac8bb88d7d5f
strongSwan 4.1.9	^78fdd287def01a3f074b5369eab4fd1c
strongSwan 4.1.8	^66a2045507c119da78a4666259cdea48
strongSwan 4.1.7	^ea840aa4dfc9712d6c32b5a16eb329a3
strongSwan 4.1.6	^d19683368af4b0edc21ccde982b1d1b0
strongSwan 4.1.5	^bf0fbf7306ebb7827042d893539886e2
strongSwan 4.1.4	^312f9cb1a6b90e19de7528c904ac3087
strongSwan 4.1.3	^5849ab6d8beabd6e4d09e5a3b88c089a
strongSwan 4.1.2	^15a1ace7ee52fddfef04f928db2dd134
strongSwan 4.1.1	^d3f1c488c368175d5f40a8f5ca5f5e12
strongSwan 4.1.0	^4794cef6843422980d1a3d06af41c5cd
strongSwan 4.0.7	^ab0746221cc8fd0d5238f73a9b3da557
strongSwan 4.0.6	^4c90136946577b51919d8d9a6b8e4a9f
strongSwan 4.0.5	^dd180d21e5ce655a768ba32211dd8ad9
strongSwan 4.0.4	^1ef283f83549b5ff9608b6d634f84d75
strongSwan 4.0.3	^b181b18e114fc209b3c6e26c3a80718e
strongSwan 4.0.2	^77e8eea6f556a499de3ffe7f7f95661c
strongSwan 4.0.1	^9dbbafcf1db0dd595ae065294003ad3e
strongSwan 4.0.0	^2ce9c946a4c879bf11b50b76cc5692cb
strongSwan 2.8.7	^3a0d4e7ca4e492ed4dfe476d1ac6018b
strongSwan 2.8.6	^fe3f49706e26a9fb36a87bfce9ea36ce
strongSwan 2.8.5	^4c7efa31b39e510432a317570d97bbb9
strongSwan 2.8.4	^76c72bfd398424dd001b86d0012fe061
strongSwan 2.8.3	^fb4641ad0eeb2a34491d15f4eff51063
strongSwan 2.8.2	^299932277b7dfe382ce23465333a7d23
strongSwan 2.8.1	^e37f2d5ba89a62cd202ee27dac06c8a8
strongSwan 2.8.0	^32f0e9b9c06dfe8c9ad5599a636971a1
strongSwan 2.7.3	^7f50cc4ebf04c2d9da73abfd69b77aa2
strongSwan 2.7.2	^a194e2aaddd0bafb95253dd96dc733eb
strongSwan 2.7.1	^8134878582121785ba65ea345d6ba724
strongSwan 2.7.0	^07fa128e4754f9447b1dd46374eef360
strongSwan 2.6.4	^b927f95219a0fe3600dba3c1182ae55f
strongSwan 2.6.3	^b2860e7837f711bef3d0eeb106872ded
strongSwan 2.6.2	^5b1cd6fe7d050eda6c93871c107db3d2
strongSwan 2.6.1	^66afbc12bbfe6ce108b1f69f4bc917b7
strongSwan 2.6.0	^3f3266499ffdbd85950e702298062844
strongSwan 2.5.7	^1f4442296b83d7e33a8b45209ba0e590
strongSwan 2.5.6	^3c5eba3d8564928e32ae43c3d9924dee
strongSwan 2.5.5	^3f267ed621ada7ee6c7d8893ccb0b14b
strongSwan 2.5.4	^7a6bf5b7df89642a75a78ef7d657c1c0
strongSwan 2.5.3	^df5b1f0f1d5679d9f8512b16c55a6065
strongSwan 2.5.2	^861ce5eb72164b190e9e629a31cf4901
strongSwan 2.5.1	^9a4a4648f60f8eda7cfcbfe271ee5b7d
strongSwan 2.5.0	^9eb3d907ed7ada4e3cbcacb917abc8e4
strongSwan 2.4.4	^485a70361b4433b31dea1c6be0df243e
strongSwan 2.4.3	^982b7a063a33c143a8eadc88249f6bcc
strongSwan 2.4.2	^e7a3fd0c6d771a8f1b8a86a4169c9ea4
strongSwan 2.4.1	^75b0653cb281eb26d31ede38c8e1e228
strongSwan 2.4.0	^e829c88149bab3c0cee85da60e18ae9b
strongSwan 2.3.2	^42a4834c92ab9a7777063afa254bcb69
strongSwan 2.3.1	^f697c1afcc2ec8ddcdf99dc7af03a67f
strongSwan 2.3.0	^b8f92b2fa2d3fe5fe158344bda1cc6ae
strongSwan 2.2.2	^99dc7cc823376b3b33d04357896ae07b
strongSwan 2.2.1	^d9118b1e9de5efced9cc9d883f2168ff
strongSwan 2.2.0	^85b6cbec480d5c8cd9882c825ac2c244

# ZyXEL ZyWALL router
# Observed on several devices.  HTTP interface shows that they are XyWALL
# I suspect that this VID is an SHA-1 hash of something because of the length
ZyXEL ZyWALL Router	^b858d1addd08c1e8adafea150608aa4497aa6cc8
ZyXEL ZyWall USG 100	^f758f22668750f03b08df6ebe1d0


# Microsoft Initial Contact
# VID is MD5 hash of "Vid-Initial-Contact"
Microsoft Initial-Contact	^26244d38eddb61b3172a36e3d0cfb819

# FreeS/WAN and Openswan
# VID is a 12-byte printable string.  The first two bytes are "OE", which
# stands for "Opportunistic Encryption" (the FreeS/WAN designers were
# enthusiastic about opportunistic encryption); the remaining ten bytes are
# a truncated, "ASCIIfied" MD5 hash of the implementation name given below.
# The "ASCIIfication" process involves clearing bit 7 and setting bit 6 in
# each byte, thus constraining the range to 64-127 inclusive.
# I think that support for this VID was added in FreeS/WAN 2.00, and carried
# over into openswan 2.x.
Linux FreeS/WAN 0.5	^4f454a734e486b4a4c656272
Linux FreeS/WAN 0.6	^4f456c4f6b6251695c7c4674
Linux FreeS/WAN 0.7	^4f4548604f7f426647775453
Linux FreeS/WAN 0.7.1	^4f456462595d67595351445c
Linux FreeS/WAN 0.7.2	^4f457c625363787f517e6544
Linux FreeS/WAN 0.8	^4f4569517b587444694c4367
Linux FreeS/WAN 0.8.1	^4f45776a7f6d5e7a415d6f7c
Linux FreeS/WAN 0.8.2	^4f454f575c595a744a7d4f78
Linux FreeS/WAN 0.8.3	^4f45676a5553715e794f4f48
Linux FreeS/WAN 0.8.4	^4f45664250754b79577f5d55
Linux FreeS/WAN 0.8.5	^4f45615f4d44507343785d7b
Linux FreeS/WAN 0.9	^4f45494f5e4f746c57664157
Linux FreeS/WAN 0.9.1	^4f45494654445c41425d6d7b
Linux FreeS/WAN 0.9.10	^4f45497d4f7e6e5d60525170
Linux FreeS/WAN 0.9.11	^4f454b486274755358555140
Linux FreeS/WAN 0.9.12	^4f45694146645c4d4362727b
Linux FreeS/WAN 0.9.13	^4f45556c7d7671444b474c59
Linux FreeS/WAN 0.9.14	^4f456640625376587d626277
Linux FreeS/WAN 0.9.15	^4f454b796672767d437d5d5a
Linux FreeS/WAN 0.9.16	^4f454f62767d78797d7f6579
Linux FreeS/WAN 0.9.17	^4f45565b597d556e596e5e60
Linux FreeS/WAN 0.9.18	^4f45637e47544c77644a5b76
Linux FreeS/WAN 0.9.19	^4f45614d4873425c42727b63
Linux FreeS/WAN 0.9.2	^4f456171784e6b594a497058
Linux FreeS/WAN 0.9.20	^4f455c6d6c497f764f44477b
Linux FreeS/WAN 0.9.21	^4f4560624076527767787c56
Linux FreeS/WAN 0.9.22	^4f4541687e4c507a405d5146
Linux FreeS/WAN 0.9.23	^4f457841597142737f44787d
Linux FreeS/WAN 0.9.24	^4f457145706b5560634e725f
Linux FreeS/WAN 0.9.25	^4f454e5b60465a5a53656967
Linux FreeS/WAN 0.9.26	^4f45677c575b4c7c6a4a7173
Linux FreeS/WAN 0.9.27	^4f455f7f606c66424e616a60
Linux FreeS/WAN 0.9.28	^4f454e6d545e534c4a626063
Linux FreeS/WAN 0.9.29	^4f45765a4a6a51584653424e
Linux FreeS/WAN 0.9.3	^4f45485e6175794375444950
Linux FreeS/WAN 0.9.30	^4f45684e6772456542755d69
Linux FreeS/WAN 0.9.31	^4f45764141405f577750567b
Linux FreeS/WAN 0.9.32	^4f45546d5d704f49785e6467
Linux FreeS/WAN 0.9.33	^4f45655d786b445b75484668
Linux FreeS/WAN 0.9.34	^4f456547696d46657a4e5371
Linux FreeS/WAN 0.9.35	^4f455b76646a646f79695451
Linux FreeS/WAN 0.9.36	^4f454d596b6a6e5f56707e49
Linux FreeS/WAN 0.9.37	^4f45757b6e79665a556c6546
Linux FreeS/WAN 0.9.38	^4f455b6b636e606f5b42707b
Linux FreeS/WAN 0.9.39	^4f45677e79657a56654f7145
Linux FreeS/WAN 0.9.4	^4f4551604748445356727b74
Linux FreeS/WAN 0.9.40	^4f456e504e735f4f67555d5f
Linux FreeS/WAN 0.9.5	^4f4549557964647c42614440
Linux FreeS/WAN 0.9.6	^4f4570695578777266796a56
Linux FreeS/WAN 0.9.7	^4f457b4a767a6f716e48566c
Linux FreeS/WAN 0.9.8	^4f455b71457d4f685c475d6c
Linux FreeS/WAN 0.9.9	^4f455e4f4d58404f604d595c
Linux FreeS/WAN 1.0.0	^4f457f685e7d4c5645785669
Linux FreeS/WAN 1.0.1	^4f457176515f515f71526b56
Linux FreeS/WAN 1.0.2	^4f45465d56636a5149725558
Linux FreeS/WAN 1.1.0	^4f454644595a4f5c7a535445
Linux FreeS/WAN 1.1.1	^4f456842537e5a5c71527547
Linux FreeS/WAN 1.1.2	^4f457d5b4a707d736e7b5b6f
Linux FreeS/WAN 1.1.3	^4f45646357714a755b4a5b72
Linux FreeS/WAN 1.1.4	^4f454160444e745150604e47
Linux FreeS/WAN 1.1.5	^4f4544547476647754795157
Linux FreeS/WAN 1.1.6	^4f454b48657b616b494a4c77
Linux FreeS/WAN 1.2.0	^4f45544e79737d4953437b43
Linux FreeS/WAN 1.2.1	^4f454d524173695157515375
Linux FreeS/WAN 1.2.2	^4f45465e5c62774e59774c4f
Linux FreeS/WAN 1.3.0	^4f455a717b40607977577067
Linux FreeS/WAN 1.3.1	^4f457d7c696569676a6f607c
Linux FreeS/WAN 1.3.2	^4f457c6f70766b5a61546a51
Linux FreeS/WAN 1.3.3	^4f457d5b527b6c54736d447d
Linux FreeS/WAN 1.3.4	^4f454e746f4f53427579497d
Linux FreeS/WAN 1.3.5	^4f45415262734d596d56516b
Linux FreeS/WAN 1.3.6	^4f456248514f405942447c4e
Linux FreeS/WAN 1.4.0	^4f45404063756a5d496a584f
Linux FreeS/WAN 1.4.1	^4f455f526760425742497c65
Linux FreeS/WAN 1.4.2	^4f456270434d5b6e6753776e
Linux FreeS/WAN 1.4.3	^4f457a6d5b605b7d42405a67
Linux FreeS/WAN 1.4.4	^4f457177674d6a63426e4d54
Linux FreeS/WAN 1.4.5	^4f457d73435c6d5b6e777d59
Linux FreeS/WAN 1.4.6	^4f45425261435763654e5269
Linux FreeS/WAN 1.4.7	^4f457a6a547b434378757857
Linux FreeS/WAN 1.4.8	^4f455476696c4e50675f6e70
Linux FreeS/WAN 1.5.0	^4f455676404f5b55457d5479
Linux FreeS/WAN 1.5.1	^4f45617072517b7d5c607344
Linux FreeS/WAN 1.5.2	^4f456f407272744071414846
Linux FreeS/WAN 1.5.3	^4f4547425f74447179614445
Linux FreeS/WAN 1.5.4	^4f457d667c7069487e495448
Linux FreeS/WAN 1.5.5	^4f45505f70774e73435e5b7a
Linux FreeS/WAN 1.6.0	^4f45467c4d4760617f486547
Linux FreeS/WAN 1.6.1	^4f454b534c5842715a656f49
Linux FreeS/WAN 1.6.2	^4f4557464c67535540427a72
Linux FreeS/WAN 1.6.3	^4f457d60727152596653686e
Linux FreeS/WAN 2.00	^4f45486b7d44784d42676b5d
Linux FreeS/WAN 2.01	^4f457c4f547e6e615b426e56
Linux FreeS/WAN 2.02	^4f456c6b44696d7f6b4c4e60
Linux FreeS/WAN 2.03	^4f45566671474962734e6264
Linux FreeS/WAN 2.04	^4f45704f736579505c6e5f6d
Linux FreeS/WAN 2.05	^4f457271785f4c7e496f4d54
Linux FreeS/WAN 2.06	^4f457e4c466e5d427c5c6b52

# Generated using openswan-vid.pl logic
# - confirmed behavior on Openswan 2.6.28 on Ubuntu
Openswan 2.1.0	^4f455d787a5b6948787a655b
Openswan 2.1.1	^4f45466a786e57484d4d4361
Openswan 2.1.2	^4f4555656771407e63636578
Openswan 2.2.0	^4f4548724b6e5e68557c604f
Openswan 2.3.0	^4f4572696f5c77557f746249
Openswan 2.3.1	^4f45454355706e735d625c71
Openswan 2.4.0	^4f45785c567c6f61507e7864
Openswan 2.4.1	^4f456e5e4c737d7d62796c51
Openswan 2.4.10	^4f456971726d54726e464a71
Openswan 2.4.11	^4f4550484948576e64636f6b
Openswan 2.4.12	^4f456c7c5b79725e4a6a5658
Openswan 2.4.13	^4f45445e597f60634770436c
Openswan 2.4.14	^4f454c4e767d475b775e6f56
Openswan 2.4.15	^4f45675d5e5d7f664c604651
Openswan 2.4.2	^4f45666a6343554b5f7a4062
Openswan 2.4.3	^4f4547407c7673775449546e
Openswan 2.4.4	^4f45565e6441545f4a664642
Openswan 2.4.5	^4f45587d5d4b4b7c61487b7c
Openswan 2.4.6	^4f45636e6542785f6f6b7257
Openswan 2.4.7	^4f4552756a414d79434d4951
Openswan 2.4.8	^4f457a6d734b6f476273616c
Openswan 2.4.9	^4f45414c5d6a75516450457a
Openswan 2.5.0	^4f4546477e5e4b5440606859
Openswan 2.5.00	^4f45495c767449495c5a7350
Openswan 2.5.01	^4f457260466858434c7e6a45
Openswan 2.5.02	^4f45717a7c715b657c5c5156
Openswan 2.5.03	^4f456651517b4f475276654d
Openswan 2.5.04	^4f455672606d794f697d7242
Openswan 2.5.05	^4f454a4d5e5e674c604e4168
Openswan 2.5.06	^4f454a6176624e5876754d64
Openswan 2.5.07	^4f455c47464946434875464e
Openswan 2.5.08	^4f455a6f776e666c49497b68
Openswan 2.5.09	^4f454c4f577c5a7c4c665248
Openswan 2.5.10	^4f45714250575765766a6c72
Openswan 2.5.11	^4f457a795c6440407166776c
Openswan 2.5.12	^4f4549796c524b7c515b5450
Openswan 2.5.13	^4f45455740667a5f766d785d
Openswan 2.5.14	^4f45736b7f50645f6c416341
Openswan 2.5.15	^4f45675e407f696148444f7c
Openswan 2.5.16	^4f4557575d58474e5d574e58
Openswan 2.5.17	^4f457a74437b794a6148685b
Openswan 2.5.18	^4f455e74654a504c7a614967
Openswan 2.6.01	^4f45766b71776b6f48467a69
Openswan 2.6.02	^4f455f525758674a61465b6b
Openswan 2.6.03	^4f45775376797c60516a757b
Openswan 2.6.04	^4f45736f4c6569475a7d7f4c
Openswan 2.6.05	^4f457b654a44434170427663
Openswan 2.6.06	^4f454a4376414f737d6e495f
Openswan 2.6.07	^4f45466b5d7b4753765c686b
Openswan 2.6.08	^4f457d456755615659534c7b
Openswan 2.6.09	^4f455a447e4d547d6d416e6c
Openswan 2.6.10	^4f45744a61537c7646486641
Openswan 2.6.11	^4f455e7f4c79574b43455465
Openswan 2.6.12	^4f45775b5b5e5b705443404e
Openswan 2.6.13	^4f455a7f4b47466754526564
Openswan 2.6.14	^4f456f534a55776561714158
Openswan 2.6.15	^4f4563476e586e5f567a5457
Openswan 2.6.16	^4f456a7d637357765a5c7b63
Openswan 2.6.17	^4f4554704245584355764571
Openswan 2.6.18	^4f457d5a765a404d5b4f5744
Openswan 2.6.19	^4f456b71484c42504f664d44
Openswan 2.6.20	^4f4543714271574c644b7a41
Openswan 2.6.21	^4f457e717f6b5a4e727d576b
Openswan 2.6.22	^4f456c6a405d72544d42754d
Openswan 2.6.23	^4f456d406b6753464548407f
Openswan 2.6.24	^4f45557d6068416e77737478
Openswan 2.6.25	^4f4543606e547b776f5e5848
Openswan 2.6.26	^4f45504b7e7a764d4e645f57
Openswan 2.6.27	^4f456e544e77494c76567e5c
Openswan 2.6.28	^4f45517b4f7f6e657a7b4351
Openswan 2.6.29	^4f455e5a65725d6564727763
Openswan 2.6.30	^4f457656736b546968656675
Openswan 2.6.31	^4f457d476e447f5a4159655b
Openswan 2.6.32	^4f4568794c64414365636661
Openswan 2.6.33	^4f456768495f775c414c4679
Openswan 2.6.34	^4f457f7e637f7679517f4a5a
Openswan 2.6.35	^4f457e487a746b6f69705842
Openswan 2.6.36	^4f45716c74725d4b5a6c5d5f
Openswan 2.6.37	^4f45755c645c6a795c5c6170
Openswan 2.6.38	^4f4576795c6b677a57715c73
Openswan 2.6.39	^4f456d6470475f6c477d767d

# General pattern, must come after specific FreeS/WAN and OpenSwan patterns.
FreeS/WAN or OpenSWAN	^4f45[[:xdigit:]]{20}$

#Libreswan was forked from Openswan 2.6.38, which was forked from
#FreeS/WAN 1.99.  This signature was taken from Libreswan 3.3 running 
#on Fedora Core 19 x86_64.  It appears like the same scheme as openswan, 
#but I can't seem to tease out the source string syntax just yet.
Libreswan 3.3	^4f454e574547444b6865684a

# OpenPGP
# VID starts with ASCII "OpenPGP".  This is generally followed by some extra
# data, e.g. "OpenPGP10171", but we don't match that.
OpenPGP	^4f70656e504750

# Observed on Fortinet ForteGate Firewalls.
# Probably an MD5 hash of something.
FortiGate	^1d6e178f6c2c0be284985465450fe9d4

# Juniper NetScreen running ScreenOS
#
# There are many different entries for this implementation, because the VID
# varies depending on the s/w version and h/w model, and maybe other things
# as well.
#
# The first 20 bytes are suspected to be an SHA1 hash of something.
# This suspected hash appears to include the s/w version and the h/w platform.
#
# This is followed by eight bytes, which we don't include in the pattern.
# This eight bytes consists of two four-byte values in big endian format,
# e.g. 0000000900000500, the last four bytes appear to indicate the ScreenOS
# version.
#
# Examples:
#
# For the examples below, we show the entire VID, the netscreen model, and
# the ScreenOS version number.
#
# 64405f46f03b7660a23be116a1975058e69e83870000000400000403 ns5xp 4.0.3r3.0
# 299ee8289f40a8973bc78687e2e7226b532c3b760000000900000500 ns5xp 5.0.0r1.0
# 299ee8289f40a8973bc78687e2e7226b532c3b760000000900000500 ns5xp 5.0.0r6.0
# 299ee8289f40a8973bc78687e2e7226b532c3b760000000900000500 ns5xp 5.0.0r9.0
# 4a4340b543e02b84c88a8b96a8af9ebe77d9accc0000000b00000500 ns5gt 5.0.0r7.1
# 2a2bcac19b8e91b426107807e02e7249569d6fd30000000b0000050a ns5gt 5.1.0r1.0
# 166f932d55eb64d8e4df4fd37e2313f0d0fd84510000000000000000 ns5gt 5.2.0r3b.0
# 166f932d55eb64d8e4df4fd37e2313f0d0fd84510000000000000000 ns5gt 5.3.0r4.0
# 166f932d55eb64d8e4df4fd37e2313f0d0fd84510000000000000000 ns5gt 5.4.0r1.0
# a35bfd05ca1ac0b3d2f24e9e82bfcbff9c9e52b50000000b00000514 unknown unknown
#
# The Netscreen hardware referenced above is:
#
# ns5xp model NS-5XP
# ns5gt	model NS-5GT-103 serial no 0064062004015770
#
# Netscreens also return:
# 4865617274426561745f4e6f74696679386b0100 (Heartbeat Notify)
# In addition, ScreenOS Version 5.3 and 5.4 returns:
# afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection)
#
Netscreen-01	^299ee8289f40a8973bc78687e2e7226b532c3b76
Netscreen-02	^3a15e1f3cf2a63582e3ac82d1c64cbe3b6d779e7
Netscreen-03	^47d2b126bfcd83489760e2cf8c5d4d5a03497c15
Netscreen-04	^4a4340b543e02b84c88a8b96a8af9ebe77d9accc
Netscreen-05	^64405f46f03b7660a23be116a1975058e69e8387
Netscreen-06	^699369228741c6d4ca094c93e242c9de19e7b7c6
Netscreen-07	^8c0dc6cf62a0ef1b5c6eabd1b67ba69866adf16a
Netscreen-08	^92d27a9ecb31d99246986d3453d0c3d57a222a61
Netscreen-09	^9b096d9ac3275a7d6fe8b91c583111b09efed1a0
Netscreen-10	^bf03746108d746c904f1f3547de24f78479fed12
Netscreen-11	^c2e80500f4cc5fbf5daaeed3bb59abaeee56c652
Netscreen-12	^c8660a62b03b1b6130bf781608d32a6a8d0fb89f
Netscreen-13	^f885da40b1e7a9abd17655ec5bbec0f21f0ed52e
Netscreen-14	^2a2bcac19b8e91b426107807e02e7249569d6fd3
Netscreen-15	^166f932d55eb64d8e4df4fd37e2313f0d0fd8451
Netscreen-16	^a35bfd05ca1ac0b3d2f24e9e82bfcbff9c9e52b5
Netscreen-16	^9436e8d67174ef9aed068d5ad5213f187a3f8ba6

# Avaya
# Observed on Avaya VSU 100R
# Not sure if this is common to all Avaya equipment
avaya	^4485152d18b6bbcc0be8a8469579ddcc

# Stonegate
# Observed on Stonesoft StoneGate v2.2.1
StoneGate-01	^c573b056d7faca36c2fba28374127cbf
StoneGate-02	^baeb239037e17787d730eed9d95d48aa

# Symantec Raptor / Enterprise Firewall
# Observed on Symantec Enterprise Firewall 8.0 running on Windows 2000
# An example vendor ID returned by these systems is:
# 526170746f7220506f77657256706e20536572766572205b56382e315d
# which corresponds to the ASCII string: "Raptor PowerVpn Server [V8.1]"
# 
Symantec-Raptor-v8.1	^526170746f7220506f77657256706e20536572766572205b56382e315d
Symantec-Raptor	^526170746f7220506f77657256706e20536572766572

# Other things I've seen but not fully classified yet.
# If anyone can confirm any of these, please let me know.
Maybe Cisco IOS	^bdb41038a7ec5e5534dd004d0f91f927
# Unknown 1 was classified as Cisco VPN Concentrator
# Unknown 2 was classified as Windows-2000
Unknown 3	^edea53a3c15d45cafb11e59ea68db2aa99c1470e0000000400000303
Unknown 4	^bedc86dabf0ab7973870b5e6c4b87d3ee824de310000001000000401
Unknown 5	^ac5078c25cabb9523979978e76a3d0d2426bc9260000000400000401
# Unknown 6 was classified as SSH IPSEC Express 4.1.0
Unknown 7	^69b761a173cc1471dc4547d2a5e94812
Unknown 8	^4c5647362e303a627269636b3a362e302e353732
Unknown 9	^3499691eb82f9eaefed378f5503671debd0663b4000000040000023c
# I've seen Unknown 10 sent from SonicWall Global VPN Client
Unknown 10	^975b7816f69789600dda89040576e0db
# The "Safenet or Watchguard" Vendor ID has also been seen sent from SonicWall
# Global VPN client.  It is normally followed by 80010000, which looks like a
# version number.
Safenet or Watchguard	^da8e9378
Unknown-cisco	^e23ae9f51a46876ff93d89ba725d649d
Maybe Sidewinder G2	^8404adf9cda05760b2ca292e4bff537b
Maybe Sidewinder G2	^e720cdd49d2ee7b83ce1970a6c69b528

# Added from wireshark database

Ssh Communications Security IPSEC Express version 1.1.0	^fbf47614984031fa8e3bb6198089b223
Ssh Communications Security IPSEC Express version 1.1.1	^1952dc91ac20f646fb01cf42a33aee30
Ssh Communications Security IPSEC Express version 1.1.2	^e8bffa643e5c8f2cd10fda7370b6ebe5
Ssh Communications Security IPSEC Express version 1.2.1	^c1111b2dee8cbc3d620573ec57aab9cb
Ssh Communications Security IPSEC Express version 1.2.2	^09ec27bfbc09c75823cfecbffe565a2e
SSH Communications Security IPSEC Express version 2.0.0	^7f21a596e4e318f0b2f4944c2384cb84
SSH Communications Security IPSEC Express version 2.1.0	^2836d1fd2807bc9e5ae30786320451ec
SSH Communications Security IPSEC Express version 2.1.1	^a68de756a9c5229bae66498040951ad5
SSH Communications Security IPSEC Express version 2.1.2	^3f2372867e237c1cd8250a75559cae20
SSH Communications Security IPSEC Express version 3.0.0	^0e58d5774df602007d0b02443660f7eb
SSH Communications Security IPSEC Express version 3.0.1	^f5ce31ebc210f44350cf71265b57380f
SSH Communications Security IPSEC Express version 4.0.0	^f64260af2e2742daddd56987068a99a0
SSH Communications Security IPSEC Express version 4.0.1	^7a54d3bdb3b1e6d923892064be2d981c
SSH Communications Security IPSEC Express version 4.1.0	^9aa1f3b43472a45d5f506aeb260cf214
SSH Communications Security IPSEC Express version 4.1.1	^89f7b760d86b012acf263382394d962f
SSH Communications Security IPSEC Express version 4.2.0	^6880c7d026099114e486c55430e7abee
SSH Communications Security IPSEC Express version 5.0	^b037a21aceccb5570f602546f97bde8c
SSH Communications Security IPSEC Express version 5.0.0	^2b2dad97c4d140930053287f996850b0
SSH Communications Security IPSEC Express version 5.1.0	^45e17f3abe93944cb202910c59ef806b
SSH Communications Security IPSEC Express version 5.1.1	^5925859f7377ed7816d2fb81c01fa551
SSH Sentinel	^054182a07c7ae206f9d2cf9d2432c482
SSH Sentinel 1.1	^b91623e693ca18a54c6a2778552305e8
SSH Sentinel 1.2	^5430888de01a31a6fa8f60224e449958
SSH Sentinel 1.3	^7ee5cb85f71ce259c94a5c731ee4e752
SSH Sentinel 1.4	^63d9a1a7009491b5a0a6fdeb2a8284f0
SSH Sentinel 1.4.1	^eb4b0d96276b4e220ad16221a7b2a5e6
SSH Communications Security QuickSec 0.9.0	^37eba0c4136184e7daf8562a77060b4a
SSH Communications Security QuickSec 1.1.0	^5d72925e55948a9661a7fc48fdec7ff9
SSH Communications Security QuickSec 1.1.1	^777fbf4c5af6d1cdd4b895a05bf82594
SSH Communications Security QuickSec 1.1.2	^2cdf08e712ede8a5978761267cd19b91
SSH Communications Security QuickSec 1.1.3	^59e454a8c2cf02a34959121f1890bc87
draft-huttunen-ipsec-esp-in-udp-00.txt	^6a7434c19d7e36348090a02334c9c805
draft-huttunen-ipsec-esp-in-udp-01.txt (ESPThruNAT)	^50760f624c63e5c53eea386c685ca083
draft-stenberg-ipsec-nat-traversal-01	^27bab5dc01ea0760ea4e3190ac27c0d0
draft-stenberg-ipsec-nat-traversal-02	^6105c422e76847e43f9684801292aecd
draft-ietf-ipsec-nat-t-ike	^4df37928e9fc4fd1b3262170d515c662
draft-ietf-ipsec-nat-t-ike-00	^4485152d18b6bbcd0be8a8469579ddcc
draft-ietf-ipsec-nat-t-ike-01	^16f6ca16e4a4066d83821a0f0aeaa862
draft-ietf-ipsec-nat-t-ike-02	^cd60464335df21f87cfdb2fc68b6a448
draft-ietf-ipsec-nat-t-ike-02\n	^90cb80913ebb696e086381b5ec427b1f
draft-ietf-ipsec-nat-t-ike-03	^7d9419a65310ca6f2c179d9215529d56
draft-ietf-ipsec-nat-t-ike-04	^9909b64eed937c6573de52ace952fa6b
draft-ietf-ipsec-nat-t-ike-05	^80d0bb3def54565ee84645d4c85ce3ee
draft-ietf-ipsec-nat-t-ike-06	^4d1e0e136deafa34c4f3ea9f02ec7285
draft-ietf-ipsec-nat-t-ike-07	^439b59f8ba676c4c7737ae22eab8f582
draft-ietf-ipsec-nat-t-ike-08	^8f8d83826d246b6fc7a8a6a428c11de8
draft-ietf-ipsec-nat-t-ike-09	^42ea5b6f898d9773a575df26e7dd19e1
Testing NAT-T RFC	^c40fee00d5d39ddb1fc762e09b7cfea7
RFC 3947 Negotiation of NAT-Traversal in the IKE	^4a131c81070358455c5728f20e95452f
draft-beaulieu-ike-xauth-02.txt	^09002689dfd6b71280a224dec33b81e5
XAUTH	^09002689dfd6b712
RFC 3706 DPD (Dead Peer Detection)	^afcad71368a1f1c96b8696fc77570100
draft-ietf-ipsec-antireplay-00.txt	^325df29a2319f2dd
draft-ietf-ipsec-heartbeats-00.txt	^8db7a41811221660
IKE Challenge/Response for Authenticated Cryptographic Keys	^ba290499c24e84e53a1d83a05e5f00c9
IKE Challenge/Response for Authenticated Cryptographic Keys	^0d33611a5d521b5e3c9c03d2fc107e12
IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)	^ad3251042cdc4652c9e0734ce5de4c7d
IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)	^013f11823f966fa91900f024ba66a86b
Microsoft L2TP/IPSec VPN Client	^4048b7d56ebce88525e7de7f00d6c2d3
Microsoft Vid-Initial-Contact	^26244d38eddb61b3172a36e3d0cfb819
A GSS-API Authentication Method for IKE	^b46d8914f3aaa3f2fedeb7c7db2943ca
A GSS-API Authentication Method for IKE	^ad2c0dd0b9c32083ccba25b8861ec455
GSSAPI	^621b04bb09882ac1e15935fefa24aeee
MS NT5 ISAKMPOAKLEY	^1e2b516905991c7d7c96fcbfb587e461
CISCO-UNITY	^12f5f28c457168a9702d9fe274cc
CISCO-CONCENTRATOR	^1f07f70eaa6514d3b0fa96542a500100
Cisco Fragmentation	^4048b7d56ebce88525e7de7f00d6c2d380000000
Cisco VPN Concentrator (IKE Fragmentation)	^4048b7d56ebce88525e7de7f00d6c2d3c0000000
CryptoPro/GOST 0.1 / Check Point R65	^f4ed19e0c114eb516faaac0ee37daf2807b4381f
CryptoPro/GOST 1.0 / Check Point R71	^031017e07f7a82e3aa6950c999990100
CryptoPro/GOST 1.1	^031017e07f7a82e3aa6950c999990101
CyberGuard	^9aa1f3b43472a45d5f506aeb26c0f214
Shrew Soft	^f14b94b7bff1fef02773b8c49feded26
strongSwan	^882fe56d6fd20dbc2251613b2ebe5beb
KAME/racoon	^7003cbc1097dbe9c2600ba6983bc8b35
IPSec-Tools	^20a3622c1cea7ce37bee3ca484425276
Netscreen-1	^299ee8289f40a8973bc78687e2e7226b532c3b76
Netscreen-2	^3a15e1f3cf2a63582e3ac82d1c64cbe3b6d779e7
Netscreen-3	^47d2b126bfcd83489760e2cf8c5d4d5a03497c15
Netscreen-4	^4a4340b543e02b84c88a8b96a8af9ebe77d9accc
Netscreen-5	^64405f46f03b7660a23be116a1975058e69e8387
Netscreen-6	^699369228741c6d4ca094c93e242c9de19e7b7c6
Netscreen-7	^8c0dc6cf62a0ef1b5c6eabd1b67ba69866adf16a
Netscreen-8	^92d27a9ecb31d99246986d3453d0c3d57a222a61
Netscreen-9 ^9b096d9ac3275a7d6fe8b91c583111b09efed1a0
Netscreen-10	^bf03746108d746c904f1f3547de24f78479fed12
Netscreen-11	^c2e80500f4cc5fbf5daaeed3bb59abaeee56c652
Netscreen-12	^c8660a62b03b1b6130bf781608d32a6a8d0fb89f
Netscreen-13	^f885da40b1e7a9abd17655ec5bbec0f21f0ed52e
Netscreen-14	^2a2bcac19b8e91b426107807e02e7249569d6fd3
Netscreen-15	^166f932d55eb64d8e4df4fd37e2313f0d0fd8451
Netscreen-16	^a35bfd05ca1ac0b3d2f24e9e82bfcbff9c9e52b5
ZYWALL	^625027749d5ab97f5616c1602765cf480a3b7d0b
SIDEWINDER	^8404adf9cda05760b2ca292e4bff537b
SonicWALL	^404bf439522ca3f6
Heartbeat Notify	^4865617274426561745f4e6f74696679
DWR: Delete with reason	^2d7922c6b301d9b0e1342739e9cfbbd5
Remote AP (Aruba Networks)	^ca3e2b854ba8030017dc1023a4fde2041f9f7463
Controller (Aruba Networks)	^3c8e70bdf9c7d74add53e4100915dc2e4bb51274
VIA Client (Aruba Networks)	^88f0e3149b3fa48b05aa7f685f0b766be186ccb8
VIA Auth Profile (Aruba Networks)	^56494120417574682050726f66696c65203a20
`
