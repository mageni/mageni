###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_itsm_faq_xss_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# OTRS ITSM FAQ XSS Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs_itsm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803941");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-2637");
  script_bugtraq_id(58930);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-27 15:11:15 +0530 (Fri, 27 Sep 2013)");
  script_name("OTRS ITSM FAQ XSS Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials..");
  script_tag(name:"vuldetect", value:"Get the installed version and location of OTRS with the help of detect NVT
and check the OTRS and OTRS:ITSM version is vulnerable or not.");
  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize user-supplied
input before using it");
  script_tag(name:"solution", value:"Upgrade to OTRS::ITSM version 3.2.4, 3.1.8 and 3.0.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with OTRS:ITSM and is prone to cross-site scripting vulnerability.");
  script_tag(name:"affected", value:"OTRS::ITSM 3.2.0 up to and including 3.2.3, 3.1.0 up to and including 3.1.7
and 3.0.0 up to and including 3.0.6");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58930");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24922/");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2012-02-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS ITSM/installed");
  script_xref(name:"URL", value:"http://www.otrs.com/en/");
  exit(0);
}


include("http_func.inc");

include("version_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(itsmvers = get_app_version(cpe:CPE, port:port))
{
  if(version_in_range(version:itsmvers, test_version:"3.2.0", test_version2:"3.2.3") ||
     version_in_range(version:itsmvers, test_version:"3.1.0", test_version2:"3.1.7") ||
     version_in_range(version:itsmvers, test_version:"3.0.0", test_version2:"3.0.6"))
  {
    security_message(port:port);
    exit(0);
  }
}
