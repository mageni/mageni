###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_connect_untrusted_search_path_vuln.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Adobe Connect Untrusted Search Path Vulnerability
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808062");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-4118");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:52 +0530 (Tue, 07 Jun 2016)");
  script_name("Adobe Connect Untrusted Search Path Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/connect/installed");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-17.html");

  script_tag(name:"summary", value:"The host is installed with Adobe Connect
  shipping an Adobe Connect Add-In for Windows which is prone to a untrusted
  search path vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Adobe Connect Add-In installer while validating the path.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users of the System which is using the vulnerable Adobe Connect Add-In to
  gain privileges via unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.5.3.");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.5.3 or
  later which ships an non-vulnerable Adobe Connect Add-In.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Users can still update their Add-In to a newer version
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

if(version_is_less(version:acVer, test_version:"9.5.3"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.5.3");
  security_message(data:report, port:acPort);
  exit(0);
}
