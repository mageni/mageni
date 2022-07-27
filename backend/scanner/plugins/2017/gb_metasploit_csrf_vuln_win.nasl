#############################################################################
# OpenVAS Vulnerability Test
#
# Metasploit Cross Site Request Forgery Vulnerability - Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:metasploit:metasploit_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811589");
  script_version("2019-05-16T08:02:32+0000");
  script_cve_id("CVE-2017-5244");
  script_bugtraq_id(99082);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-30 17:12:23 +0530 (Wed, 30 Aug 2017)");
  script_name("Metasploit Cross Site Request Forgery Vulnerability - Windows");

  script_tag(name:"summary", value:"This host is installed with Metasploit
  and is prone to a cross-site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to absence of csrf
  verification for GET requests so that the stop action could be triggered
  through GET requests, an attacker able to trick an authenticated user to
  request a URL which runs JavaScript could trigger the same action.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow a remote attacker to perform certain unauthorized actions in the
  context of the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"Metasploit before 4.14.0 (Update 2017061301)");

  script_tag(name:"solution", value:"Upgrade to the latest version Metasploit 4.14.0
  (Update 2017061301) or above.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.seekurity.com/blog/general/metasploit-web-project-kill-all-running-tasks-csrf-CVE-2017-5244");
  script_xref(name:"URL", value:"https://community.rapid7.com/community/metasploit/blog/2017/06/15/r7-2017-16-cve-2017-5244-lack-of-csrf-protection-for-stopping-tasks-in-metasploit-pro-express-and-community-editions-fixed");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_metasploit_framework_detect_win.nasl");
  script_mandatory_keys("Metasploit/Framework/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!appVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:appVer, test_version:"4.14.0"))
{
  report =  report_fixed_ver(installed_version:appVer, fixed_version:"4.14.0 (Update 2017061301)");
  security_message(data:report);
  exit(0);
}
exit(0);
