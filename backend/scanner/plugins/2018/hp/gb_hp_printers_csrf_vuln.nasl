##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printers_csrf_vuln.nasl 12590 2018-11-30 07:32:04Z asteins $
#
# HP Printers CSRF Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141573");
  script_version("$Revision: 12590 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 08:32:04 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-09 09:01:36 +0700 (Tue, 09 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-5921");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Printers CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with certain HP
printers and MFPs in 2405129_000052 and other firmware versions. This vulnerability is known as Cross Site Request
Forgery, and could potentially be exploited remotely to allow elevation of privilege.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Multiple HP LaserJet, HP Officejet, HP PageWide and HP ScanJet
devices. See the referenced advisory for an extended list.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05949322");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("hp_model"))
  exit(0);

if (!fw_ver = get_kb_item("hp_fw_ver"))
  exit(0);

if (model =~ "^Officejet Color X555") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000055")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000055");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color 556") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000051")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000051");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M606") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000046")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000046");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M607") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000069")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000069");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M608") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000069")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000069");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M609") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000069")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000069");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E60055") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000069")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000069");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet E60065") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000069")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000069");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M652") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000068")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000068");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M653") {
  if (version_is_less(version: fw_ver, test_version: "2405130_000068")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405130_000068");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet M806") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000059")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000059");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet M855") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000057")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000057");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 MFP M525") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000048")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000048");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet flow MFP M525") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000048")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000048");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M527") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000039")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000039");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M527") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000039")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000039");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 500 color MFP M575") {
  if (version_is_less(version: fw_ver, test_version: "2405135_000409")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405135_000409");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet color flow MFP M575") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000045")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000045");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP M577") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000038")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000038");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color MFP X585") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000050")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000050");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Officejet Color FlowMFP X585") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000050")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000050");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color MFP 586") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000066")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000066");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color Flow MFP 586") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000066")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000066");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color MFP E58650") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000066")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000066");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^PageWide Color Flow E58650") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000066")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000066");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M630") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000040")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000040");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M630") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000040")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000040");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M631") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000041")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000041");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M632") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000041")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000041");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet Flow MFP M633") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000041")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000041");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP E62555") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000041")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000041");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP M680") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000042")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000042");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet Flow MFP M680") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000042")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000042");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP M681") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000037")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000037");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet FlowMFP M681") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000037")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000037");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet FlowMFP M682") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000037")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000037");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP M725") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000058")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000058");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet 700 color MFP M775") {
  if (version_is_less(version: fw_ver, test_version: "2405135_000405")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405135_000405");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet flow MFP M830") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000060")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000060");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet flow MFP M880") {
  if (version_is_less(version: fw_ver, test_version: "2405129_000054")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405129_000054");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP E72525") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024821")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024821");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^LaserJet MFP E72530") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024821")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024821");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet Flow E87640") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024814")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024814");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E87650") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024814")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024814");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E77822") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024820")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024820");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E77825") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024820")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024820");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^Color LaserJet MFP E77830") {
  if (version_is_less(version: fw_ver, test_version: "2405347_024820")) {
    report = report_fixed_ver(installed_version: fw_ver, fixed_version: "2405347_024820");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
