###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_xss_n_clickjack_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# OTRS Help Desk Cross-Site Scripting and Clickjacking Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804418");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2553", "CVE-2014-2554");
  script_bugtraq_id(66569, 66567);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-07 15:00:42 +0530 (Mon, 07 Apr 2014)");
  script_name("OTRS Help Desk Cross-Site Scripting and Clickjacking Vulnerabilities");


  script_tag(name:"summary", value:"This host is running OTRS (Open Ticket Request System) and is prone to
cross-site scripting and clickjacking vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"- Certain input related to dynamic fields is not properly sanitised before
   being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
   via iframes without performing any validity checks to verify the requests.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
and clickjacking attacks.");
  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) version 3.1.x before 3.1.21,
3.2.x before 3.2.16, and 3.3.x before 3.3.6");
  script_tag(name:"solution", value:"Upgrade to OTRS version 3.1.21 or 3.2.16 or 3.3.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57616");
  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=10361");
  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=10374");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");

  script_xref(name:"URL", value:"http://www.otrs.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!otrsport = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:otrsport))
{
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.20") ||
     version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.15") ||
     version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.5"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
