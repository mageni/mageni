###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_typeinfo_code_exec_vuln.nasl 11357 2018-09-12 10:57:05Z asteins $
#
# PHP 'com_print_typeinfo()' Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902836");
  script_version("$Revision: 11357 $");
  script_bugtraq_id(53621);
  script_cve_id("CVE-2012-2376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:57:05 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-23 15:15:15 +0530 (Wed, 23 May 2012)");
  script_name("PHP 'com_print_typeinfo()' Remote Code Execution Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53621");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18861");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=13255");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=823464");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/05/20/2");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112851/php54-exec.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code in the context of a webserver. Failed attempts will likely result
  in denial of service conditions.");

  script_tag(name:"affected", value:"PHP Version 5.4.3 and prior on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'com_print_typeinfo()' function,
  which allows remote attackers to execute arbitrary code via crafted arguments
  that trigger incorrect handling of COM object VARIANT types.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to remote code
  execution vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less_equal(version:phpVer, test_version:"5.4.3")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"N/A");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
