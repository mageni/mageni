###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_consolidation.nasl 12598 2018-11-30 10:59:00Z cfischer $
#
# IBM WebSphere MQ Detection Consolidation
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141717");
  script_version("$Revision: 12598 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 11:59:00 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-28 11:36:08 +0700 (Wed, 28 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere MQ Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected IBM WebSphere MQ including the version
number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ibm_websphere_mq_detect.nasl", "gb_ibm_websphere_mq_detect_lin.nasl",
                      "gb_ibm_websphere_mq_mqi_detect.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_xref(name:"URL", value:"https://www.ibm.com/products/mq");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("ibm_websphere_mq/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("win", "lin", "mqi")) {
  version_list = get_kb_list("ibm_websphere_mq/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown")
      detected_version = vers;
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_mq:");
if (!cpe)
  cpe = 'cpe:/a:ibm:websphere_mq';

# Remote MQI
if (mqi_ports = get_kb_list("ibm_websphere_mq/mqi/port")) {
  if (!isnull(mqi_ports))
    extra += '\nRemote Detection over MQI:\n';

  foreach port (mqi_ports) {
    extra += '   Port:  ' + port + '\n';

    register_product(cpe: cpe, location: port + "/tcp", port: port, service: "websphere_mqi");
  }
}

# Linux
if (bin_path = get_kb_item("ibm_websphere_mq/lin/local/path")) {
  extra += 'Local Detection on Linux:\n';
  extra += '   Path:  ' + bin_path + '\n';

  register_product(cpe: cpe, location: bin_path, port: 0, service: "ssh-login");
}
else if (x86_path = get_kb_item("ibm_websphere_mq/win/x86/path")) {
  extra += 'Local Detection on Windows (x86):\n';
  extra += '   Path:  ' + x86_path + '\n';

  register_product(cpe: cpe, location: x86_path, port: 0, service: "smb-login");
}
else if (x64_path = get_kb_item("ibm_websphere_mq/win/x64/path")) {
  extra += 'Local Detection on Windows (x64):\n';
  extra += '   Path:  ' + x64_path + '\n';

  cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_mq:x64:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:websphere_mq:x64';

  register_product(cpe: cpe, location: x64_path, port: 0, service: "smb-login");
}

report = build_detection_report(app: "IBM WebSphere MQ", version: detected_version, cpe: cpe, extra: extra);

if (report)
  log_message(port: 0, data: report);

exit(0);
