###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_office_mult_vuln02.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cybozu Office Multiple Vulnerabilities-02 Feb16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807277");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-1150", "CVE-2016-1149", "CVE-2015-7798", "CVE-2015-7797",
                "CVE-2015-7796", "CVE-2015-7795", "CVE-2015-8487");
  script_bugtraq_id(83286, 83289);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:43 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozuo Office Multiple Vulnerabilities-02 Feb16");

  script_tag(name:"summary", value:"The host is installed with Cybozu Office
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  multiple functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause information disclosure or arbitrary script may be executed
  on the user's web browser.");

  script_tag(name:"affected", value:"Cybozu Office version 9.0.0 to 10.3.0");
  script_tag(name:"solution", value:"Upgrade to Cybozu Office version 10.4.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN47296923/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN69278491/index.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuOffice/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://products.cybozu.co.jp/office/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cybPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cybVer = get_app_version(port:cybPort, cpe:CPE)){
  exit(0);
}

if(version_in_range(version:cybVer, test_version:"9.0.0", test_version2:"10.3.0"))
{
  report = report_fixed_ver(installed_version:cybVer, fixed_version:"10.4.0");
  security_message(port:cybPort, data:report);
  exit(0);
}

exit(99);
