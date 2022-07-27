###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_register_var_fun_arbitrary_code_exec_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# PHP 'php_register_variable_ex()' Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802590");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)");
  script_name("PHP 'php_register_variable_ex()' Remote Code Execution Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47806");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72911");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.3.10");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=15408");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2012-0830");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary PHP
  code on the system.");

  script_tag(name:"affected", value:"PHP Version 5.3.9 on windows.");

  script_tag(name:"insight", value:"The flaw is due to a logic error within the 'php_register_variable_ex()'
  function in php_variables.c when hashing form posts and updating a hash table,
  which can be exploited to execute arbitrary code.");

  script_tag(name:"solution", value:"Upgrade to PHP Version 5.3.10 or later.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to remote arbitrary
  code execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_equal(version:phpVer, test_version:"5.3.9")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.10");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
