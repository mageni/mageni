###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_spectrum_scale_detect.nasl 12989 2019-01-09 10:31:15Z ckuersteiner $
#
# IBM Spectrum Scale Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141837");
  script_version("$Revision: 12989 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 11:31:15 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-09 15:31:48 +0700 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Spectrum Scale Detection");

  script_tag(name:"summary", value:"Detection of IBM Spectrum Scale.

The script sends a connection request to the server and attempts to detect IBM Spectrum Scale and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ibm.com/us-en/marketplace/scale-out-file-and-object-storage");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("Log In - IBM Spectrum Scale" >< res && 'require(["gss/Login-all"]' >< res) {
  version = "unknown";

  # var supportedRel = {"actual":"5.0.1.0","guiVersion":"5.0.1-0","expected":"4.2.0.0","supported":true};
  vers = eregmatch(pattern: 'supportedRel = \\{"actual":"([0-9.]+)"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "ibm_spectrum_scale/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:spectrum_scale:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:spectrum_scale';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM Spectrum Scale", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
