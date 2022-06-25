###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_mult_xss_vuln_lin.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# nextCloud Multiple XSS Vulnerabilities (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:nextcloud:nextcloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811137");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-0893", "CVE-2017-0891");
  script_bugtraq_id(98423, 98411);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-30 16:57:47 +0530 (Tue, 30 May 2017)");
  script_name("nextCloud Multiple XSS Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"The host is installed with nextCloud and
  is prone to multiple XSS vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exist due to

  - An inadequate escaping of error message in multiple components.

  - Nextcloud Server shipping a vulnerable JavaScript library for sanitizing
    untrusted user-input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to write or paste malicious content into the server.");

  script_tag(name:"affected", value:"nextCloud Server 9.0.x before 9.0.58, 10.0.x
  before 10.0.5 and 11.0.x before 11.0.3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to nextCloud Server 9.0.58, or 10.0.5,
  or 11.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2017-010");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2017-008");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nextPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!nextVer = get_app_version(cpe:CPE, port:nextPort)){
  exit(0);
}

if(nextVer =~ "^11\." && version_is_less(version:nextVer, test_version:"11.0.3")){
  fix = "11.0.3";
}

else if(nextVer =~ "^10\." && version_is_less(version:nextVer, test_version:"10.0.5")){
  fix = "10.0.5";
}

else if(nextVer =~ "^9\." && version_is_less(version:nextVer, test_version:"9.0.58")){
  fix = "9.0.58";
}

if(fix)
{
  report = report_fixed_ver(installed_version:nextVer, fixed_version:fix);
  security_message(data:report, port:nextPort);
  exit(0);
}
