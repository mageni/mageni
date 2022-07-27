# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108950");
  script_version("2020-10-20T06:44:37+0000");
  script_cve_id("CVE-2020-26887");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-20 10:21:19 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-20 05:45:25 +0000 (Tue, 20 Oct 2020)");
  script_name("AVM FRITZ!Box DNS Rebinding Protection Bypass (CVE-2020-26887)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://en.avm.de/service/security-information-about-updates/");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2020-003/-fritz-box-dns-rebinding-protection-bypass");

  script_tag(name:"summary", value:"Multiple AVM FRITZ!Box devices are prone to a DNS rebinding protection bypass.");

  script_tag(name:"insight", value:"FRITZ!Box router devices employ a protection mechanism against DNS rebinding
  attacks. If a DNS answer points to an IP address in the private network range of the router, the answer is
  suppressed. Suppose the FRITZ!Box routers DHCP server is in its default configuration and serves the private
  IP range of 192.168.178.1/24. If a DNS request is made by a connected device, which resolves to an IPv4 address
  in the configured private IP range (for example 192.168.178.20) an empty answer is returned. However, if
  instead the DNS answer contains an AAAA-record with the same private IP address in its IPv6 representation
  (::ffff:192.168.178.20) it is returned successfully. Furthermore, DNS requests which resolve to the loopback
  address 127.0.0.1 or the special address 0.0.0.0 can be retrieved, too.");

  script_tag(name:"impact", value:"The flaw allows to resolve DNS answers that point to IP addresses in the
  private local network, despite the DNS rebinding protection mechanism.");

  script_tag(name:"affected", value:"- AVM FRITZ!Box 6490 and 6590 running AVM FRITZ!OS before version 7.20

  - Other AVM FRITZ!Box devices running AVM FRITZ!OS before version 7.21");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Update to AVM FRITZ!OS 7.20 / 7.21 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! model = get_kb_item( "avm/fritz/model" ) )
  exit( 0 );

if( model =~ "6[45]90" )
  patch = "7.20";
else
  patch = "7.21";

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
