###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_couchdb_priv_esc_vuln_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# CouchDB 2.0.0 Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112221");
  script_cve_id("CVE-2016-8742");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12116 $");

  script_name("CouchDB 2.0.0 Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-13 09:02:26 +0100 (Tue, 13 Feb 2018)");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_couchdb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5984);
  script_mandatory_keys("couchdb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"This host is installed with Apache CouchDB and is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:'Upgrade to version 2.0.0.1 or later.

NOTE:

If an upgrade cannot be performed, the following steps will secure an existing CouchDB 2.0.0 installation:

1. In Windows Explorer, navigate to the CouchDB installation folder. Right click on the folder and select Properties.

2. In the Properties window, select the Security tab, and click on the Advanced button.

3. In the Advanced Security Settings window, click the Change Permissions... button.

4. Ensure only the following settings are listed, removing any other entries:

- Allow - Users - Read & Execute

- Allow - SYSTEM - Full control

- Allow - Administrators - Full control

5. Check the "Replace all child object permissions with inheritable permissions from this object."

6. Click OK three times to close all dialog boxes.');

  script_tag(name:"insight", value:"The Windows installer that the Apache CouchDB team provides is vulnerable to local privilege
escalation. All files in the install inherit the file permissions of the parent directory
and therefore a non-privileged user can substitute any executable for the nssm.exe service
launcher, or CouchDB batch or binary files. A subsequent service or server restart will then
run that binary with administrator privilege.");

  script_tag(name:"affected", value:"CouchDB versions 2.0.0 on Windows");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/couchdb-dev/201612.mbox/%3C825F65E1-0E5F-4E1F-8053-CF2C6200C526%40apache.org%3E");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE)) {
  exit(0);
}

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

