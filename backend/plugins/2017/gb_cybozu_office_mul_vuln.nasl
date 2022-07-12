###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_office_mul_vuln.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# Cybozu Office Multiple Security Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107149");
  script_version("$Revision: 11959 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-19 14:53:28 +0200 (Wed, 19 Apr 2017)");
  script_cve_id("CVE-2017-2114", "CVE-2017-2115", "CVE-2017-2116", "CVE-2016-4449");

  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Office Multiple Security Vulnerabilities");
  script_tag(name:"summary", value:"Cybozu Office is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, access or modify data, bypass security restrictions and perform unauthorized
  actions in the context of the affected application.");

  script_tag(name:"affected", value:"Cybozu Office 10.0.0 through 10.5.0 are vulnerable");

  script_tag(name:"solution", value:"Update to version 10.6.0.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97717");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuOffice/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(port: Port, cpe:CPE)){
  exit(0);
}

if (Ver =~ "10\.")
{
    if(version_is_less_equal(version: Ver, test_version: "10.5.0"))
    {
      report =  report_fixed_ver(installed_version:Ver, fixed_version:"10.6.0");
      security_message(port: Port, data:report);
      exit(0);
    }
}

exit(99);
