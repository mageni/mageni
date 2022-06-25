# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142861");
  script_version("2019-09-09T07:08:33+0000");
  script_tag(name:"last_modification", value:"2019-09-09 07:08:33 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-09 04:53:57 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-10058");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Account Lockout Vulnerability (TE922)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected", "lexmark_printer/model");

  script_tag(name:"summary", value:"Account lockout functionality is missing from some Lexmark devices.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Account lockout functionality for local accounts is missing from a few older
  Lexmark devices. Therefore it is possible to obtain the local account credentials by brute force.");

  script_tag(name:"impact", value:"Local account credentials may be extracted from the device via brute force
  guessing attacks.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://support.lexmark.com/index?page=content&id=TE922");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("lexmark_printer/model"))
  exit(0);

cpe = 'cpe:/o:lexmark:' + tolower(model) + "_firmware";
if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (model =~ "^CS31") {
  if (version_is_less(version: version, test_version: "lw71.vyl.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.vyl.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CS41") {
  if (version_is_less(version: version, test_version: "lw71.vy2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.vy2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CS51") {
  if (version_is_less(version: version, test_version: "lw71.vy4.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.vy4.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CX310") {
  if (version_is_less(version: version, test_version: "lw71.gm2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.gm2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(CX410|C2130)") {
  if (version_is_less(version: version, test_version: "lw71.gm4.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.gm4.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(CX510|C2132)") {
  if (version_is_less(version: version, test_version: "lw71.gm7.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.gm7.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS31[027]|MS410|M1140)") {
  if (version_is_less(version: version, test_version: "lw71.prl.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.prl.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS315|MS41[57])") {
  if (version_is_less(version: version, test_version: "lw71.tl2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.tl2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS51|MS610dn|MS617)") {
  if (version_is_less(version: version, test_version: "lw71.pr2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.pr2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(M1145|M3150dn)") {
  if (version_is_less(version: version, test_version: "lw71.pr2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.pr2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS71|M5163dn|MS81[01278])") {
  if (version_is_less(version: version, test_version: "lw71.dn2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.dn2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS810de|M5155|MS5163)") {
  if (version_is_less(version: version, test_version: "lw71.dn4.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.dn4.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS812de|M5170)") {
  if (version_is_less(version: version, test_version: "lw71.dn7.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.dn7.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^MS91") {
  if (version_is_less(version: version, test_version: "lw71.sa.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.sa.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX31|XM1135)") {
  if (version_is_less(version: version, test_version: "lw71.sb2.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.sb2.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX410|MX51[01]|XM114[05])") {
  if (version_is_less(version: version, test_version: "lw71.sb4.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.sb4.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX61[01]|XM3150)") {
  if (version_is_less(version: version, test_version: "lw71.sb7.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.sb7.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX[78]1|XM51|XM71)") {
  if (version_is_less(version: version, test_version: "lw71.tu.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.tu.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^MX6500e") {
  if (version_is_less(version: version, test_version: "lw71.jd.p230")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.jd.p230");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C746") {
  if (version_is_less(version: version, test_version: "lhs60.cm2.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.cm2.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C(S)?748") {
  if (version_is_less(version: version, test_version: "lhs60.cm4.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.cm4.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(C792|CS796)") {
  if (version_is_less(version: version, test_version: "lhs60.hc.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hc.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C925") {
  if (version_is_less(version: version, test_version: "lhs60.hv.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hv.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C950") {
  if (version_is_less(version: version, test_version: "lhs60.tp.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.tp.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?548") {
  if (version_is_less(version: version, test_version: "lhs60.vk.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.vk.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(X74|XS748)") {
  if (version_is_less(version: version, test_version: "lhs60.ny.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.ny.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(X792|XS79)") {
  if (version_is_less(version: version, test_version: "lhs60.mr.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.mr.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?925") {
  if (version_is_less(version: version, test_version: "lhs60.hk.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.hk.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X(S)?95") {
  if (version_is_less(version: version, test_version: "lhs60.tq.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.tq.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^6500e") {
  if (version_is_less(version: version, test_version: "lhs60.jr.p706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lhs60.jr.p706");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C734") {
  if (version_is_less(version: version, test_version: "lr.sk.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.sk.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^C736") {
  if (version_is_less(version: version, test_version: "lr.ske.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.ske.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^E46") {
  if (version_is_less(version: version, test_version: "lr.lbh.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.lbh.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^T65") {
  if (version_is_less(version: version, test_version: "lr.jb.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.jb.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X46") {
  if (version_is_less(version: version, test_version: "lr.bs.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.bs.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X73") {
  if (version_is_less(version: version, test_version: "lr.fl.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.fl.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^W850") {
  if (version_is_less(version: version, test_version: "lr.jb.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.jb.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^X86") {
  if (version_is_less(version: version, test_version: "lr.sp.p816")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lr.sp.p816");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
