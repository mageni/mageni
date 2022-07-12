###############################################################################
# OpenVAS Vulnerability Test
#
# evalSMSI Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800165");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("evalSMSI Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed evalSMSI version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

evalSMSIPort = get_http_port(default:80);

if( !can_host_php( port:evalSMSIPort ) ) exit( 0 );

foreach path (make_list_unique("/evalsmsi", "/", cgi_dirs(port:evalSMSIPort)))
{

  install = path;
  if( path == "/" ) path = "";

  sndReq = http_get(item: path + "/evalsmsi.php", port:evalSMSIPort);
  rcvRes = http_keepalive_send_recv(port:evalSMSIPort, data:sndReq);

  if(">EvalSMSI" >< rcvRes) {

    version = "unknown";

    evalSMSIVer = eregmatch(pattern:">EvalSMSI version ([0-9.]+) ?--", string:rcvRes);
    if(evalSMSIVer[1] != NULL) version = evalSMSIver[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + evalSMSIPort + "/evalSMSI", value:tmp_version);
    set_kb_item(name:"evalsmsi/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:myshell:evalsmsi:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:myshell:evalsmsi';

    register_product( cpe:cpe, location:install, port:evalSMSIPort );

    log_message( data: build_detection_report( app:"Eval SMSI",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: evalSMSIVer[0]),
                                               port:evalSMSIPort);
  }
}
