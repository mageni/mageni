###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_routeros_l2tp_mitm_attack_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# MikroTik RouterOS 'L2TP' Man-in-the-Middle Attack Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810609");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-6297");
  script_bugtraq_id(96447);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-09 16:21:26 +0530 (Thu, 09 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("MikroTik RouterOS 'L2TP' Man-in-the-Middle Attack Vulnerability");

  script_tag(name:"summary", value:"This host is running MikroTik router
  and is prone to a man in the middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the L2TP
  client which does not enable IPsec encryption after a reboot.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to view unencrypted transmitted data and gain access to networks on
  the L2TP server by monitoring the packets for the transmitted data and
  obtaining the L2TP secret.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions 6.83.3 and
  6.37.4");

  script_tag(name:"solution", value:"Update to version 6.37.5, 6.83.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://blog.milne.it/2017/02/24/mikrotik-routeros-security-vulnerability-l2tp-tunnel-unencrypted-cve-2017-6297");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^6\.") {
  if( version_is_equal( version:version, test_version:"6.83.3" ) ||
      version_is_equal( version:version, test_version:"6.37.4" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"6.37.5, 6.83.4 or later");
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
