###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_jk_auth_bypass_vuln.nasl 12927 2019-01-03 05:43:34Z ckuersteiner $
#
# Apache Tomcat Connector Authentication Bypass Vulnerability May15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apache:mod_jk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805612");
  script_version("$Revision: 12927 $");
  script_cve_id("CVE-2014-8111");
  script_bugtraq_id(74265);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 06:43:34 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-05-11 12:56:25 +0530 (Mon, 11 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Apache Tomcat Connector Authentication Bypass Vulnerability May15");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  Connector and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to a vulnerability in apache
  tomcat connector that is triggered due to the incorrect handling of the
  JkMount and JkUnmount directives, which can lead to the exposure of a private artifact in a tree.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat Connectors (mod_jk) before 1.2.41.");

  script_tag(name:"solution", value:"Upgrade to version 1.2.41 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://cxsecurity.com/cveshow/CVE-2014-8111");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1182591");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_mod_jk_detect.nasl");
  script_mandatory_keys("apache_modjk/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!modjkVer = get_app_version(cpe:CPE, port:http_port))
  exit(0);

if (version_is_less_equal(version:modjkVer, test_version:"1.2.40")) {
  report = report_fixed_ver(installed_version: modjkVer, fixed_version: "1.2.41");
  security_message(data:report, port:http_port);
  exit(0);
}

exit(0);
