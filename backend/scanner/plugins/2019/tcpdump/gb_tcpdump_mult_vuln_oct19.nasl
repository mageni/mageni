# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113543");
  script_version("2019-10-21T13:56:23+0000");
  script_tag(name:"last_modification", value:"2019-10-21 13:56:23 +0000 (Mon, 21 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-21 15:35:17 +0000 (Mon, 21 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-15166");

  script_name("tcpdump < 4.9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_tcpdump_ssh_detect.nasl");
  script_mandatory_keys("tcpdump/detected");

  script_tag(name:"summary", value:"tcpdump is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There are buffer over-read vulnerabilities in the following modules:

  print-ldp.c:ldp_tlv_print(), print_icmp.c:icmp_print(), print_vrrp.c:vrrp_print(),
  print_lmp.c:lmp_print_data_link_subobjs(), print_rsvp.c:rsvp_obj_print(),
  print-rx.c:rx_cache_find(), print-rx.c:rx_cache_insert(),
  print-bgp.c:bgp_capabilities_print(), print-fr.c:mfr_print(), print-isakkmp.c:ikev1_n_print(),
  print_babel.c:babel_print_v2(), print-ospf6.c:ospf6_print_lshdr(), print-icmp6.c,
  print-802_11.c, print-hncp.c:print_prefix(), print-dccp.c:dccp_print_option(),
  print_bgp.c:bgp_attr_print(), print-smb.c:print_trans()

  There is a buffer overflow vulnerability in tcpdump.c:get_next_file().

  There is a stack consumption vulnerability in print-bgp.c:bgp_attr_print().

  There is a stack exhaustion vulnerability in smbutil.c:smb_fdata().

  print_lmp.c:lmp_print_data_link_subobjs() lacks bounds checks.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information
  or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"tcpdump through version 4.9.2.");

  script_tag(name:"solution", value:"Update to version 4.9.3.");

  script_xref(name:"URL", value:"https://www.tcpdump.org/tcpdump-changes.txt");

  exit(0);
}

CPE = "cpe:/a:tcpdump:tcpdump";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.3", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
