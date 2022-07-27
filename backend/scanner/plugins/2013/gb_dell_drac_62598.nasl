###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_62598.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Dell iDRAC6 and iDRAC7 'ErrorMsg' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103808");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-14 11:13:22 +0200 (Mon, 14 Oct 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12175 $");

  script_bugtraq_id(62598);
  script_cve_id("CVE-2013-3589");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell iDRAC6 and iDRAC7 'ErrorMsg' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62598");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/920038");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dell_drac_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dell_idrac/installed", "dell_idrac/generation");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
browser of an unsuspecting user in the context of the affected site. This may let the attacker steal cookie-based
authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"insight", value:"Dell iDRAC 6 and Dell iDRAC 7 administrative web interface login page can
allow remote attackers to inject arbitrary script via the vulnerable query string parameter ErrorMsg.");

  script_tag(name:"solution", value:"Firmware updates will be posted to the Dell support page when available.
Users should download the appropriate update for the version of iDRAC they have installed:

iDRAC6 'monolithic' (rack and towers) - FW version 1.96.

iDRAC7 all models - FW version 1.46.45");

  script_tag(name:"summary", value:"Dell iDRAC6 and iDRAC7 are prone to a cross-site scripting vulnerability
because they fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"Dell iDRAC6 1.95 and previous versions, Dell iDRAC7 1.40.40 and previous
versions.

NOTE: iDRAC6 'modular' (blades) are not affected, no updates are required.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:dell:idrac6", "cpe:/a:dell:idrac7");
if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

port = infos['port'];

generation = get_kb_item("dell_idrac/generation");
if (!generation)
  exit(0);

cpe = "cpe:/a:dell:idrac" + generation;
if (!version = get_app_version(cpe: cpe))
  exit(0);

if (generation == "6") {
  if (version_is_less(version: version, test_version: "1.96")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.96");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (generation == "7") {
  if (version_is_less(version: version, test_version: "1.46.45")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.46.45");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
