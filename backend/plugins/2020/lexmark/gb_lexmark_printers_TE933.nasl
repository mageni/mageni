# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143529");
  script_version("2020-02-19T06:33:25+0000");
  script_tag(name:"last_modification", value:"2020-02-19 06:33:25 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 06:03:11 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2019-18791");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer XSS Vulnerability (TE933)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected", "lexmark_printer/model");

  script_tag(name:"summary", value:"A stored cross-site scripting vulnerability has been identified in some
  Lexmark devices.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting vulnerability has been identified in the
  embedded web server used in older generation Lexmark devices. The vulnerability can be used to attack the users
  browser, exposing session credentials and other information accessible to the browser.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can lead to disclosure of
  information accessible to the browser.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://support.lexmark.com/index?page=content&id=TE933");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("lexmark_printer/model"))
  exit(0);

cpe = 'cpe:/o:lexmark:' + tolower(model) + "_firmware";
if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (model =~ "^CX31[^0]") {
  if (version_is_less(version: version, test_version: "lw73.vyl.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.vyl.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CX41[^0]") {
  if (version_is_less(version: version, test_version: "lw73.vy2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.vy2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CX51[^0]") {
  if (version_is_less(version: version, test_version: "lw73.vy4.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.vy4.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CX310") {
  if (version_is_less(version: version, test_version: "lw73.gm2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.gm2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(CX410|C2130)") {
  if (version_is_less(version: version, test_version: "lw73.gm4.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.gm4.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(CX510|C2132)") {
  if (version_is_less(version: version, test_version: "lw73.gm7.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.gm7.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS31[027]|MS410|M1140)") {
  if (version_is_less(version: version, test_version: "lw73.prl.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.prl.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS315|MS41[57])") {
  if (version_is_less(version: version, test_version: "lw73.tl2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.tl2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS51|MS610dn|MS617)") {
  if (version_is_less(version: version, test_version: "lw73.pr2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.pr2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(M1145|M3150dn)") {
  if (version_is_less(version: version, test_version: "lw73.pr2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.pr2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS610de|M3150)") {
  if (version_is_less(version: version, test_version: "lw73.pr4.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.pr4.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS71|M5163dn|MS81[01278])") {
  if (version_is_less(version: version, test_version: "lw73.dn2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.dn2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS810de|M5155|MS5163)") {
  if (version_is_less(version: version, test_version: "lw73.dn4.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.dn4.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS812de|M5170)") {
  if (version_is_less(version: version, test_version: "lw73.dn7.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.dn7.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^MS91") {
  if (version_is_less(version: version, test_version: "lw73.sa.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.sa.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX31|XM1135)") {
  if (version_is_less(version: version, test_version: "lw73.sb2.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.sb2.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX410|MX51[01]|XM114[05])") {
  if (version_is_less(version: version, test_version: "lw73.sb4.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.sb4.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX61[01]|XM3150)") {
  if (version_is_less(version: version, test_version: "lw73.sb7.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.sb7.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX[78]1|XM51|XM71)") {
  if (version_is_less(version: version, test_version: "lw73.tu.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.tu.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX91|XM91)") {
  if (version_is_less(version: version, test_version: "lw73.mg.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.mg.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^MX6500e") {
  if (version_is_less(version: version, test_version: "lw73.jd.p264")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw73.jd.p264");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C746") {
  if (version_is_less(version: version, test_version: "lhs60.cm2.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.cm2.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C(S)?748") {
  if (version_is_less(version: version, test_version: "lhs60.cm4.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.cm4.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(C792|CS796)") {
  if (version_is_less(version: version, test_version: "lhs60.hc.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hc.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C925") {
  if (version_is_less(version: version, test_version: "lhs60.hv.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hv.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C950") {
  if (version_is_less(version: version, test_version: "lhs60.tp.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.tp.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?548") {
  if (version_is_less(version: version, test_version: "lhs60.vk.p698")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.vk.p698");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(X74|XS748)") {
  if (version_is_less(version: version, test_version: "lhs60.ny.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.ny.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(X792|XS79)") {
  if (version_is_less(version: version, test_version: "lhs60.mr.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.mr.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?925") {
  if (version_is_less(version: version, test_version: "lhs60.hk.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hk.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?95") {
  if (version_is_less(version: version, test_version: "lhs60.tq.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.tq.p732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^6500e") {
  if (version_is_less(version: version, test_version: "lhs60.jr.p732")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.jr.732");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C734") {
  if (version_is_less_equal(version: version, test_version: "lr.sk.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C736") {
  if (version_is_less_equal(version: version, test_version: "lr.ske.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^E46") {
  if (version_is_less_equal(version: version, test_version: "lr.lbh.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^T65") {
  if (version_is_less_equal(version: version, test_version: "lr.jb.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X46") {
  if (version_is_less_equal(version: version, test_version: "lr.bs.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X65") {
  if (version_is_less_equal(version: version, test_version: "lr.mn.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X73") {
  if (version_is_less_equal(version: version, test_version: "lr.fl.p822")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^W850") {
  if (version_is_less_equal(version: version, test_version: "lr.jb.p821")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X86") {
  if (version_is_less_equal(version: version, test_version: "lr.sp.p821")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
