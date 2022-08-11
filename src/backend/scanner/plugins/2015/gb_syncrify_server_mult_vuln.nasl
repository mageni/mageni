###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syncrify_server_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Syncrify Server Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:syncrify:server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805551");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3140");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-12 10:45:47 +0530 (Tue, 12 May 2015)");
  script_name("Syncrify Server Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Syncrify Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the input passed via the
  'adminEmail', 'smtpUser' and 'fullName' parameters is not validated before
  returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct CSRF attacks and execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Syncrify Server 3.6 Build 833 and prior.");

  script_tag(name:"solution", value:"Upgrade to Syncrify Server 3.6 Build 834
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36950");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_syncrify_server_detect.nasl");
  script_mandatory_keys("syncrify/installed");
  script_xref(name:"URL", value:"http://www.synametrics.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!serPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!serVer = get_app_version(cpe:CPE, port:serPort)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"3.6")){
  VULN = TRUE;
}

if(version_is_equal(version:serVer, test_version:"3.6"))
{
  builVer = get_kb_item("syncrify/" + serPort + "/build");

  if(version_is_less_equal(version:builVer, test_version:"833")){
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed Version: ' + serVer + '\nFixed Version: 3.6 Build 834\n';
  security_message(data:report, port:serPort);
  exit(0);
}
