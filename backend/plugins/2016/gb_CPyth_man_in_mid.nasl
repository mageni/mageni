###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CPyth_man_in_mid.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# CPython Man In The Middle Attack Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:python:python';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107021");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2013-7440");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"creation_date", value:"2016-07-04 19:31:49 +0200 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CPython Man In The Middle Attack Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_Python_detection.nasl");
  script_mandatory_keys("pyVer/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"CPython before 2.7.9 and 3.x before 3.3.3 suffers from a man in the middle attack vulnerability via a crafted certificate.");
  script_tag(name:"insight", value:"The ssl.match_hostname function in CPython does not properly handle wildcards in hostnames,
  which might allow man-in-the-middle attackers to spoof servers via a crafted certificate.");
  script_tag(name:"impact", value:"Allows unauthorized modification.");
  script_tag(name:"affected", value:"CPython before 2.7.9 and 3.x before 3.3.3.");
  script_tag(name:"solution", value:"Upgrade to 3.3.3 or a higher version if Python 3.x is installed, otherwise: upgrade to 2.7.9 or a higher version.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)) exit(0);
if(!appVer = get_app_version(cpe:CPE, port:appPort)) exit(0);

if(appVer =~ "^(3\.)" && version_is_less(version:appVer, test_version:"3.3.3")) {
  VUL = TRUE;
  Fixed_Version = "3.3.3 or higher";
}
else if(version_is_less(version:appVer, test_version:"2.7.9")){
  VUL = TRUE;
  Fixed_Version = "2.7.9 or higher";
}

if(VUL){
  report = report_fixed_ver(installed_version:appVer, fixed_version:Fixed_Version);
  security_message(port:appPort, data:report);
  exit(0);
}

exit(99);
