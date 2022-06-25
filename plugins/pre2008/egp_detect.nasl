###############################################################################
# OpenVAS Vulnerability Test
#
# EGP detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# See RFC 827 & RFC 888

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11908");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("EGP detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Service detection");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"If this protocol is not needed, disable it or filter incoming traffic going
  to IP protocol #8");

  script_tag(name:"summary", value:"The remote host is running EGP, an obsolete routing protocol.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("network_func.inc");

if(islocalhost() || TARGET_IS_IPV6() )
  exit(0);

s = this_host();
v = eregmatch(pattern:"^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string:s);
if(isnull(v))
  exit(0);

for(i = 1; i <=4; i++)
  a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

r = raw_string(	2,      # EGP version
                3,      # Type
                0,      # Code = Neighbor Acquisition Request
                0,      # Info (not used here)
                0, 0,   # checksum
                a1, a2, # Autonomous system
                s1, s2, # Identification
                0, 30, # NR Hello Interval
                0, 120 # NR Poll Interval
);

ck = ip_checksum(data:r);
r2 = insstr(r, ck, 4, 5);

egp = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_p:8, ip_ttl:64,
                      ip_off:0, ip_src:this_host(), data:r2);

f = "ip proto 8 and src " + get_host_ip();
for( i = 0; i < 3; i++ ) {
  r = send_packet(egp, pcap_active:TRUE, pcap_filter:f, pcap_timeout:1);
  if(r)
    break;
}

if(isnull(r))
  exit(0);

hl = ord(r[0]) & 0xF; hl *= 4;
egp = substr(r, hl);
if (ord(egp[0]) == 2 && ord(egp[1]) == 3 && ord(egp[2]) <= 4)
  log_message(port:0, proto:"egp");
