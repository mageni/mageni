################################################################################
# OpenVAS Vulnerability Test
#
# Brother HL Series Printer Cross-Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813391");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-11581");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_name("Brother HL Series Printer Cross-Site Scripting Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_brother_hl_series_printer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Brother/HL/Printer/model", "Brother/HL/Printer/version");

  script_xref(name:"URL", value:"https://gist.github.com/huykha/409451e4b086bfbd55e28e7e803ae930");

  script_tag(name:"summary", value:"This host is running Brother HL Series Printer
  and is prone to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to am improper validation of
  url parameter to 'etc/loginerror.html'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary html and script code into the web site.
  This would alter the appearance and would make it possible to initiate further
  attacks against site visitors.");

  script_tag(name:"affected", value:"Brother HL-L2340D and HL-L2380DW series
  printers Firmware prior to 1.16.");

  script_tag(name:"solution", value:"Update the printer to Firmware 1.16 or
  later and set a new password. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/h:brother:hl-l2340d", "cpe:/h:brother:hl-l2380dw");

if(!infos = get_single_app_ports_from_list(cpe_list:cpe_list))
  exit(0);

CPE  = infos['cpe'];
port = infos['port'];

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.16")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.16", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);