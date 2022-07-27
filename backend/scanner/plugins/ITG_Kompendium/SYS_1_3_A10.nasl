# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_version("2021-03-12T14:23:19+0000");
  script_oid("1.3.6.1.4.1.25623.1.0.150588");
  script_tag(name:"last_modification", value:"2021-03-12 14:23:19 +0000 (Fri, 12 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-10 09:31:46 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");

  script_name("SYS.1.3.A10");

  script_category(ACT_GATHER_INFO);
  script_family("IT-Grundschutz");
  script_dependencies("os_detection.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_1_3_Server_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=3");
  script_tag(name:"summary", value:"Dienste und Anwendungen SOLLTEN mit einer individuellen
Sicherheitsarchitektur geschuetzt werden (z. B. mit AppArmor oder SELinux). Auch chroot-Umgebungen
sowie LXC- oder Docker-Container SOLLTEN dabei beruecksichtigt werden. Es SOLLTE sichergestellt sein,
dass mitgelieferte Standardprofile bzw. -regeln aktiviert sind.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen";

if (host_runs("linux") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.3.A10");
  exit(0);
}

desc = itg_no_automatic_test();
result = itg_no_automatic_test();
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:result, default:"None", compliant:"yes", fixtext:"None",
  type:"None", test:"None", info:desc);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.3.A10");
itg_report(report:report);

exit(0);