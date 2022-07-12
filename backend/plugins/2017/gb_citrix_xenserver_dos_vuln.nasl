###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_xenserver_dos_vuln.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# Citrix XenServer CVE-2017-5572 Denial of Service Vulnerability
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

CPE = 'cpe:/a:citrix:xenserver';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107212");
  script_version("$Revision: 11959 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-31 19:18:23 +0200 (Wed, 31 May 2017)");
  script_cve_id("CVE-2017-5572");

  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix XenServer CVE-2017-5572 Denial of Service Vulnerability");
  script_tag(name:"summary", value:"Citrix XenServer is prone to a denial-of-service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to cause denial-of-service condition.");
  script_tag(name:"affected", value:"Citrix XenServer 6.0.2, Citrix XenServer 7.0, Citrix XenServer 6.5 SP1,
  Citrix XenServer 6.5, Citrix XenServer 6.2.0 Sp1, Citrix XenServer 6.2");
  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95801");
  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220112");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_xenserver_web_detect.nasl");
  script_mandatory_keys("citrix_xenserver/webgui/detected");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if (version_is_equal(version:Ver, test_version:"6.0.2") || version_is_equal(version:Ver, test_version:"6.5.2")
    || version_is_equal(version:Ver, test_version:"6.2") || version_is_equal(version:Ver, test_version:"7.0")) {
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"Apply the specific hotfix supplied by the vendor.");
  security_message(port:Port, data:report);
  exit(0);
}

exit (99);

