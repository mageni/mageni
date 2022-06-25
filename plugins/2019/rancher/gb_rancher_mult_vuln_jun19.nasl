# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113038");
  script_version("2019-06-12T09:56:27+0000");
  script_tag(name:"last_modification", value:"2019-06-12 09:56:27 +0000 (Wed, 12 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 14:44:30 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12274", "CVE-2019-11881");

  script_name("Rancher < 2.2.4 Mutliple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_rancher_detect.nasl");
  script_mandatory_keys("rancher/installed");

  script_tag(name:"summary", value:"Rancher is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Unprivileged users (if allowed to deploy nodes) can gain admin access to the
    Rancher management plane because node driver options intentionally allow
    posting certain data to the cloud. The problem is that a user could choose
    to post a sensitive file such as /root/.kube/config or
    /var/lib/rancher/management-state/cred/kubeconfig-system.yaml.

  - A content spoofing vulnerability exists in the login component, where the errorMsg parameter
    can be tampered to display arbitrary content, filtering tags but not special
    characters or symbols. There's no other limitation of the message.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain admin access.
  It might allow malicious users to lure legitimate users to visit phishing sites - for example with scare tactics.");
  script_tag(name:"affected", value:"Rancher through version 2.2.3.");
  script_tag(name:"solution", value:"Update to version 2.2.4.");

  script_xref(name:"URL", value:"https://forums.rancher.com/t/rancher-release-v2-2-4-addresses-rancher-cve-2019-12274-and-cve-2019-12303/14466");
  script_xref(name:"URL", value:"https://github.com/MauroEldritch/VanCleef");
  script_xref(name:"URL", value:"https://github.com/rancher/rancher/issues/20216");

  exit(0);
}

CPE = "cpe:/a:rancher:rancher";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
