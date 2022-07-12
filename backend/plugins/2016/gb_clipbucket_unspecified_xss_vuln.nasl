###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipbucket_unspecified_xss_vuln.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# ClipBucket Unspecified Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:clipbucket_project:clipbucket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809039");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-4848");
  script_bugtraq_id(92537);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-08 14:26:07 +0530 (Thu, 08 Sep 2016)");
  script_name("ClipBucket Unspecified Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with ClipBucket
  and is prone to an unspecified cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input via unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may let the attacker steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"ClipBucket version before 2.8.1 RC2");

  script_tag(name:"solution", value:"Upgrade to clipBucket version 2.8.1 RC2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000140.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://clipbucket.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!clipPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!clipVer = get_app_version(cpe:CPE, port:clipPort)){
  exit(0);
}

if(version_is_less(version:clipVer, test_version:"2.8.1.RC.2"))
{
  report = report_fixed_ver(installed_version:clipVer, fixed_version:"2.8.1 RC2");
  security_message(data:report, port:clipPort);
  exit(0);
}
