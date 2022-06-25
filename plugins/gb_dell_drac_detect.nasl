###############################################################################
# OpenVAS Vulnerability Test
#
# Dell Remote Access Controller Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103680");
  script_version("2019-05-03T12:35:22+0000");
  script_tag(name:"last_modification", value:"2019-05-03 12:35:22 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Dell Remote Access Controller Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Dell Remote Access Controller.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:443 );

# iDRAC9
url = "/restgui/locale/personality/personality_en.json";
res = http_get_cache(port: port, item: url);

if ('"app_name": "Integrated Remote Access Controller 9"' >< res) {
  version = "unknown";

  url = "/sysmgmt/2015/bmc/info";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # {"Attributes":{"ADEnabled":"Disabled","BuildVersion":"30","FwVer":"3.21.21.21","GUITitleBar":"iDRAC-716GFV2","IsOEMBranded":"1","License":"Enterprise","SSOEnabled":"Disabled","SecurityPolicyMessage":"By accessing this computer, you confirm that such access complies with your organization's security policy.","ServerGen":"14G","SystemLockdown":"Disabled","SystemModelName":"Not Available","TFAEnabled":"Disabled","iDRACName":"iDRAC-716GFV2"}}
  vers = eregmatch(pattern: '"FwVer":"([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac9:");
  if (!cpe)
    cpe = 'cpe:/a:dell:idrac9';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Dell iDRAC9", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);

  exit(0);
}

# some newer versions like iDRAC7/8
url = "/login.html";
req = http_get_req(port: port, url: "/login.html", add_headers: make_array("Accept-Encoding", "gzip, deflate"));
res = http_keepalive_send_recv(port: port, data: req);

if ('<title id="titleLbl_id"></title>' >< res && "log_thisDRAC" >< res) {
  version = "unknown";

  url = '/session?aimGetProp=fwVersionFull';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: 'fwVersionFull" :"([^(" ]+)( \\(Build ([0-9]+)\\))?', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;

    if (!isnull(vers[3])) {
      build = vers[3];
      set_kb_item(name: "dell_idrac/build", value: build);
      extra = "Build:  " + build;
    }
  }

  set_kb_item(name: "dell_idrac/installed", value: TRUE);

  req = http_post_req( port: port, url: "/data?get=prodServerGen");
  res = http_keepalive_send_recv(port: port, data: req);

  generation = "";
  gen = eregmatch(pattern: "<prodServerGen>([^<]+)", string: res);
  if (!isnull(gen[1])) {
    if (gen[1] == "12G") {
      generation = "7";
      set_kb_item(name: "dell_idrac/generation", value: generation);
    }
    else if (gen[1] == "13G") {
      generation = "8";
      set_kb_item(name: "dell_idrac/generation", value: generation);
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac" + generation + ":");
  if (!cpe)
    cpe = 'cpe:/a:dell:idrac' + generation;

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Dell iDRAC" + generation, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

# Testing for older versions
urls = make_array();

urls['/cgi/lang/en/login.xsl'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/public/about.html'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';
urls['/cgi/about'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/Applications/dellUI/Strings/EN_about_hlp.htm'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';

info_url[4] = make_list('/cgi/about');
info_url_regex[4] = make_list('var s_build = "([^"]+)"');

info_url[5] = make_list('/cgi-bin/webcgi/about');
info_url_regex[5] = make_list('<FirmwareVersion>([^<]+)</FirmwareVersion>');

info_url[6] = make_list('/public/about.html','/Applications/dellUI/Strings/EN_about_hlp.htm');
info_url_regex[6] = make_list('Version ([^<]+)<br>','var fwVer = "([^"]+)";','Version ([0-9.]+)');

info_url[7] = make_list('/public/about.html');
info_url_regex[7] = make_list('var fwVer = "([^("]+)";');

foreach url ( keys( urls ) )
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! buf ) continue;

  if( ! egrep( pattern:urls[url], string:buf ) ) continue;

  version = eregmatch( pattern:urls[url], string:buf );
  if( isnull( version[1] ) ) continue;

  set_kb_item(name: "dell_idrac/installed", value: TRUE);
  generation = version[1];
  if (!isnull(version[1]))
    set_kb_item(name: "dell_idrac/generation", value: generation);

  iv = int( version[1] );
  iv_urls = info_url[iv];

  if( iv_urls )
  {
    foreach iv_url ( iv_urls )
    {
      req = http_get( item:iv_url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( ! buf || "HTTP/1\.1 404" >< buf ) continue;

      foreach iur (info_url_regex[iv])
      {
        fw_version = eregmatch( pattern:iur, string:buf );
        if( ! isnull( fw_version[1] ) )
        {
          fw = fw_version[1];
          concUrl = iv_url;
          break;
        }
      }

      if( fw )
      {
        if("(Build" >< fw )
        {
          f = eregmatch( pattern:'^([0-9.]+)\\(Build ([0-9]+)\\)', string:fw );
          if( ! isnull( f[1] ) ) fw = f[1];
          if( ! isnull( f[2] ) )
            set_kb_item(name: "dell_idrac/build", value: f[2]);
            extra = "Build:  " + f[2];
        }
        break;
      }
    }
  }

  cpe = build_cpe(value: fw, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac" + generation + ":");
  if (!cpe)
    cpe = 'cpe:/a:dell:idrac' + generation;

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app:"Dell iDRAC" + generation, version: fw, install: "/", cpe: cpe,
                                           concluded: fw_version[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit( 0 );
}

exit( 0 );
