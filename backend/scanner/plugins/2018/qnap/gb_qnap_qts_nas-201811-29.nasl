###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_nas-201811-29.nasl 12912 2018-12-31 08:46:47Z asteins $
#
# QNAP QTS < 4.2.6 build 20180829 XSS Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108493");
  script_version("$Revision: 12912 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-31 09:46:47 +0100 (Mon, 31 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-03 10:27:18 +0100 (Mon, 03 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-0716");

  script_name("QNAP QTS < 4.2.6 build 20180829 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to a XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site scripting vulnerability has been reported to affect Qsync Central
  included within QNAP QTS.");

  script_tag(name:"impact", value:"If successfully exploited, the vulnerability could allow remote attackers to inject
  Javascript code in the compromised application.");

  script_tag(name:"affected", value:"QTS 4.2.6 build 20180711 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20180829 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201811-29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# TODO:
# - Use get_all_apps_port_from_list()
# - Advisory is also referring to Qsync Central versions on 4.3+ which we're currently not detecting.

if( ! model = get_kb_item( "qnap/model" ) ) exit( 0 );
CPE = "cpe:/h:qnap:" + tolower( model );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "4.2.6_20180829" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.6 build 20180829" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
