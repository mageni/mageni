###############################################################################
# OpenVAS Vulnerability Test
#
# QNAP QTS Photo Station Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.813164");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-03 19:51:43 +0530 (Thu, 03 May 2018)");
  script_name("QNAP QTS Photo Station Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  QNAP QTS Photo Station.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/port");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# Photo Station is part of QNAP QTS
if (!qtsPort = get_kb_item("qnap/port"))
  exit(0);

foreach dir (make_list("/photo/", "/photo/gallery/", "/gallery/"))
{
  req = http_get_req( url:dir, port:qtsPort, add_headers:make_array("Accept-Encoding", "gzip, deflate"));
  res = http_keepalive_send_recv(port:qtsPort, data:req);

  if(res =~ "^HTTP/1\.[01] 30.")
  {
    url = eregmatch(pattern: 'Location: ([^\r\n]+)', string: res);
    if(url[1])
    {
      new_url = url[1];
      req = http_get_req( url:new_url, port:qtsPort);
      res = http_keepalive_send_recv(port:qtsPort, data:req);
      if(res !~ "^HTTP/1\.[01] 200"){
        continue ;
      }
    }
  }

  if(res =~ "^HTTP/1\.[01] 200" && "title>Photo Station</title" >< res)
  {
    url = eregmatch(pattern:"'\.js\?([0-9.]+)", string:res);
    new_url = dir + "/lang/ENG.js?" + url[1] ;
    req = http_get_req( url:new_url, port:qtsPort);
    res = http_keepalive_send_recv(port:qtsPort, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "QTS Login" >< res && res =~ "COPYRIGHT=.*QNAP Systems" &&
      "LANG_QTS" >< res)
    {
      photoVer = "Unknown";
      set_kb_item(name:"QNAP/QTS/PhotoStation/detected", value:TRUE);

      url = dir + "/api/user.php" ;
      req = http_get_req( url:url, port:qtsPort);
      res = http_keepalive_send_recv(port:qtsPort, data:req);
      if(res =~ "^HTTP/1\.[01] 200" && "status" >< res && "timestamp" >< res)
      {
        version = eregmatch(pattern:'<appVersion>([0-9.]+)</appVersion><appBuildNum>([0-9]+)<', string:res);
        baseQTSVersion = eregmatch(pattern:'<builtinFirmwareVersion>([0-9.]+)</builtinFirmwareVersion>', string:res);
        if(!isnull(version[1])) {
          photoVer = version [1];
          concUrl = url;
          set_kb_item(name:"QNAP/QTS/PhotoStation/version", value: photoVer);
          if(version[2]) {
            photoBuild = version [2];
            set_kb_item(name:"QNAP/QTS/PhotoStation/build", value: photoBuild);
          }
          if(baseQTSVersion[1]) {
            baseQTSVer = baseQTSVersion[1];
            set_kb_item(name:"QNAP/QTS/PS/baseQTSVer", value: baseQTSVer);
          }
        }

        cpe = build_cpe(value:photoVer, exp:"^([0-9.]+)", base:"cpe:/a:qnap:photo_station");
        if(isnull(cpe))
          cpe = "cpe:/a:qnap:photo_station";

        register_product(cpe:cpe, location:dir, port:qtsPort);

        log_message(data: build_detection_report(app:"QNAP QTS Photo Station", version:photoVer, install:dir,
                                                 cpe:cpe, concludedUrl:concUrl, concluded: version[0]),
                    port:qtsPort);
        exit(0);
      }
    }
  }
}
exit(0);
