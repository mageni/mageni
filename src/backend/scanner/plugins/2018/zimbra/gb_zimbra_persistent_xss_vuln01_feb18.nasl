################################################################################
# OpenVAS Vulnerability Test
#
# Zimbra Collaboration Suite Persistent XSS Vulnerability-01 Feb18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812800");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-8783");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-07 15:10:19 +0530 (Wed, 07 Feb 2018)");
  script_name("Zimbra Collaboration Suite Persistent XSS Vulnerability-01 Feb18");

  script_tag(name:"summary", value:"This host is running Zimbra Collaboration
  Suite and is prone to persistent XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  error while opening an email in the conversation view of the web interface.");

  script_tag(name:"impact", value:"This issue allows an attacker to perform a
  wide variety of actions such as performing arbitrary actions on their behalf
  or presenting a fake login screen to collect usernames and passwords.");

  script_tag(name:"affected", value:"Synacor Zimbra Collaboration Suite (ZCS)
  before 8.7.10");

  script_tag(name:"solution", value:"Upgrade to version 8.7.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20170409/cross-site-scripting-vulnerability-in-zimbra-collaboration-suite.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_admin_console_detect.nasl");
  script_mandatory_keys("zimbra_web/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.zimbra.com/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!zimport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:zimport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"8.7.10"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.7.10", install_path:path);
  security_message(data:report, port:path);
  exit(0);
}
exit(0);
