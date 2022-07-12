###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_dir_trav_vuln_aug14.nasl 12926 2019-01-03 03:38:48Z ckuersteiner $
#
# vTiger CRM 'file' Arbitrary File Disclosure Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804748");
  script_version("$Revision: 12926 $");
  script_cve_id("CVE-2014-1222");
  script_bugtraq_id(66136);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2014-08-25 15:26:37 +0530 (Mon, 25 Aug 2014)");

  script_name("vTiger CRM 'file' Arbitrary File Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Vtiger CRM and is prone to arbitrary file
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the /kcfinder/browse.php script not properly sanitizing user
  input, specifically path traversal style attacks (e.g. '../') supplied via the 'file' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker to gain
  access to arbitrary files.");

  script_tag(name:"affected", value:"Vtiger CRM version 6.0.0 and prior.");

  script_tag(name:"solution", value:"Apply the patch 'Vtiger CRM 6.0.0 Security patch 1' or upgrade to the latest
version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57149");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125685");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-1222");
  script_xref(name:"URL", value:"http://softlayer-sng.dl.sourceforge.net/project/vtigercrm/vtiger%20CRM%206.0.0/Add-ons/vtigercrm-600-security-patch1.zip");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");
  script_require_ports("Services/www", 80, 8888);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!vtVer = get_app_version(cpe:CPE, port:http_port))
  exit(0);

if(version_is_less_equal(version:vtVer, test_version:"6.0.0")) {
  report = report_fixed_ver(installed_version: vtVer, fixed_version: "Apply patch.");
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);
