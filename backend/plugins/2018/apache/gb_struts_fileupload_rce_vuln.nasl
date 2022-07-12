# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141668");
  script_version("2021-03-31T14:01:21+0000");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-11-08 13:09:14 +0700 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-1000031");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts 2.x <= 2.3.36 commons-fileupload RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) in a shipped library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"There exists a Java Object in the Apache Commons
  FileUpload library that can be manipulated in such a way that when it is deserialized,
  it can write or copy files to disk in arbitrary locations. Furthermore, while the Object
  can be used alone, this new vector can be integrated with ysoserial to upload and
  execute binaries in a single deserialization call. This may or may not work depending on
  an application's implementation of the FileUpload library.

  Apache Struts version 2.3.36 and prior contain the affected Commons FileUpload library.");

  script_tag(name:"affected", value:"Apache Struts 2.0 through 2.3.36.");

  script_tag(name:"solution", value:"Update to version 2.5.12 or later.");

  script_xref(name:"URL", value:"https://mail-archives.us.apache.org/mod_mbox/www-announce/201811.mbox/%3CCAMopvkMo8WiP%3DfqVQuZ1Fyx%3D6CGz0Epzfe0gG5XAqP1wdJCoBQ%40mail.gmail.com%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];

if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.3.36")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.5.12", install_path:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);