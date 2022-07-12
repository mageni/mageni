###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_mult_vuln.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# OTRS Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804236");
  script_version("$Revision: 14185 $");
  script_cve_id("CVE-2014-1471", "CVE-2014-1694");
  script_bugtraq_id(65217, 65241);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-07 18:02:09 +0530 (Fri, 07 Feb 2014)");
  script_name("OTRS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with OTRS (Open Ticket Request System) and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"- Flaw is in State.pm script, which fail to sufficiently sanitize user
  supplied data.

  - Multiple scripts in Kernel/Modules/ fails to perform certain actions
 via HTTP requests without performing any validity checks to verify the requests");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code or perform unauthorized actions in the context of a logged-in user.");

  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) 3.1.x before 3.1.19, 3.2.x before 3.2.14,
  and 3.3.x before 3.3.4.");

  script_tag(name:"solution", value:"Upgrade to OTRS 3.1.19 or 3.2.14 or 3.3.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56644");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56655");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-02-sql-injection-issue");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-01-csrf-issue-customer-web-interface");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!otrsport = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:otrsport))
{
  if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.13") ||
     version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.18") ||
     version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.3"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
