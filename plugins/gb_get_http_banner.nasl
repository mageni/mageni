###############################################################################
# OpenVAS Vulnerability Test
#
# HTTP Banner
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140170");
  script_version("2019-05-23T10:58:26+0000");
  script_tag(name:"last_modification", value:"2019-05-23 10:58:26 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2017-02-21 11:53:19 +0100 (Tue, 21 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Banner");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script get the HTTP banner and store some values in the KB related to this banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

function set_mandatory_key( key, regex, banner, extra_key ) {

  local_var key, regex, banner, extra_key;

  if( ! key )   return;
  if( ! regex ) return;
  if( ! banner ) return;

  if( egrep( pattern:regex, string:banner, icase:TRUE ) ) {
    set_kb_item( name:key + "/banner", value:TRUE );
    if( extra_key )
      set_kb_item( name:extra_key, value:TRUE );
  }
  return;
}

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

set_mandatory_key( key:"uc_httpd", regex:"Server: uc-httpd", banner:banner );
set_mandatory_key( key:"MyServer", regex:"MyServer ([0-9.]+)", banner:banner );
set_mandatory_key( key:"Ipswitch", regex:"Server: Ipswitch", banner:banner );
set_mandatory_key( key:"EasyFileSharingWebServer", regex:"Server: Easy File Sharing Web Server", banner:banner );
set_mandatory_key( key:"Abyss", regex:"Abyss", banner:banner );
set_mandatory_key( key:"Sun-Java-System-Web-Proxy-Server", regex:"Server: Sun-Java-System-Web-Proxy-Server", banner:banner );
set_mandatory_key( key:"IBM_HTTP_Server", regex:"Server: IBM_HTTP_Server", banner:banner );
set_mandatory_key( key:"GoAhead-Webs", regex:"Server: GoAhead", banner:banner );
set_mandatory_key( key:"zope", regex:"Zope", banner:banner );
set_mandatory_key( key:"ELOG_HTTP", regex:"Server: ELOG HTTP", banner:banner );
set_mandatory_key( key:"dwhttpd", regex:"dwhttpd", banner:banner );
set_mandatory_key( key:"Zervit", regex:"Server: Zervit", banner:banner );
set_mandatory_key( key:"apache", regex:"Server: Apache", banner:banner );
set_mandatory_key( key:"CommuniGatePro", regex:"Server: CommuniGatePro", banner:banner );
set_mandatory_key( key:"WinGate", regex:"WinGate", banner:banner );
set_mandatory_key( key:"thin", regex:"Server: thin", banner:banner );
set_mandatory_key( key:"Cherokee", regex:"Cherokee", banner:banner );
set_mandatory_key( key:"corehttp", regex:"Server: corehttp", banner:banner );
set_mandatory_key( key:"RaidenHTTPD", regex:"Server: RaidenHTTPD", banner:banner );
set_mandatory_key( key:"InterVations", regex:"Server:.*InterVations", banner:banner );
set_mandatory_key( key:"Monkey", regex:"Server: Monkey", banner:banner );
set_mandatory_key( key:"Savant", regex:"Server: Savant", banner:banner );
set_mandatory_key( key:"Jetty", regex:"Server: Jetty", banner:banner );
set_mandatory_key( key:"Polipo", regex:"Server: Polipo", banner:banner );
set_mandatory_key( key:"iWeb", regex:"Server: iWeb", banner:banner );
set_mandatory_key( key:"HWS", regex:"Server: .*\(HWS[0-9]+\)", banner:banner );
set_mandatory_key( key:"Serv-U", regex:"Server: Serv-U", banner:banner );
set_mandatory_key( key:"uhttps", regex:"Server: uhttps", banner:banner );
set_mandatory_key( key:"Weborf", regex:"Server: Weborf", banner:banner );
set_mandatory_key( key:"Boa", regex:"Server: Boa", banner:banner );
set_mandatory_key( key:"minaliC", regex:"Server: minaliC", banner:banner );
set_mandatory_key( key:"tracd", regex:"Server: tracd", banner:banner );
set_mandatory_key( key:"Wing_FTP_Server", regex:"Server: Wing FTP Server", banner:banner );
set_mandatory_key( key:"httpdx", regex:"httpdx", banner:banner, extra_key:"www_or_ftp/httpdx/detected" );
set_mandatory_key( key:"bozohttpd", regex:"Server: bozohttpd", banner:banner );
set_mandatory_key( key:"AOLserver", regex:"AOLserver", banner:banner );
set_mandatory_key( key:"SunWWW", regex:"Server: Sun-", banner:banner );
set_mandatory_key( key:"Zeus", regex:"Server: Zeus", banner:banner );
set_mandatory_key( key:"kolibri", regex:"erver: kolibri", banner:banner );
set_mandatory_key( key:"TopCMM", regex:"Server: TopCMM Server", banner:banner );
set_mandatory_key( key:"onehttpd", regex:"Server: onehttpd", banner:banner );
set_mandatory_key( key:"swebs", regex:"Server: swebs", banner:banner );
set_mandatory_key( key:"JibbleWebServer", regex:"Server: JibbleWebServer", banner:banner );
set_mandatory_key( key:"httpd", regex:"Server: httpd", banner:banner );
set_mandatory_key( key:"MiniWebSvr", regex:"MiniWebSvr", banner:banner );
set_mandatory_key( key:"Yaws", regex:"Server: Yaws", banner:banner );
set_mandatory_key( key:"Orion", regex:"Server: Orion", banner:banner );
set_mandatory_key( key:"LiteSpeed", regex:"LiteSpeed", banner:banner );
set_mandatory_key( key:"Play_Framework", regex:"Server: Play. Framework", banner:banner );
set_mandatory_key( key:"WEBrick", regex:"Server: WEBrick", banner:banner );
set_mandatory_key( key:"SaServer", regex:"Server: SaServer", banner:banner );
set_mandatory_key( key:"Varnish", regex:"X-Varnish", banner:banner );
set_mandatory_key( key:"3S_WebServer", regex:"Server: 3S_WebServer", banner:banner );
set_mandatory_key( key:"nostromo", regex:"Server: nostromo", banner:banner );
set_mandatory_key( key:"sharepoint", regex:"sharepoint", banner:banner );
set_mandatory_key( key:"Oracle-Application-Server", regex:"Oracle-Application-Server", banner:banner );
set_mandatory_key( key:"Easy_Chat_Server", regex:"Easy Chat Server", banner:banner );
set_mandatory_key( key:"Hiawatha", regex:"Server: Hiawatha", banner:banner );
set_mandatory_key( key:"SiteScope", regex:"SiteScope", banner:banner );
set_mandatory_key( key:"jHTTPd", regex:"Server: jHTTPd", banner:banner );
set_mandatory_key( key:"Serva32", regex:"Server: Serva32", banner:banner );
set_mandatory_key( key:"CarelDataServer", regex:"Server: CarelDataServer", banner:banner );
set_mandatory_key( key:"TOSHIBA", regex:"Server: TOSHIBA", banner:banner );
set_mandatory_key( key:"Mojolicious", regex:"Server: Mojolicious", banner:banner );
set_mandatory_key( key:"IceWarp", regex:"IceWarp", banner:banner );
set_mandatory_key( key:"Xitami", regex:"Server: Xitami", banner:banner );
set_mandatory_key( key:"wodWebServer", regex:"wodWebServer", banner:banner );
set_mandatory_key( key:"RT-N56U", regex:'Basic realm="RT-N56U"');
set_mandatory_key( key:"HomeSeer", regex:"Server: HomeSeer", banner:banner );
set_mandatory_key( key:"LilHTTP", regex:"Server: LilHTTP", banner:banner );
set_mandatory_key( key:"Univention", regex:"Univention", banner:banner );
set_mandatory_key( key:"DHost", regex:"Server: DHost.+HttpStk", banner:banner );
set_mandatory_key( key:"surgemail", regex:"surgemail", banner:banner );
set_mandatory_key( key:"TD_Contact_Management_Server", regex:"Server: TD Contact Management Server", banner:banner );
set_mandatory_key( key:"Herberlin_Bremsserver", regex:"Server: Herberlin Bremsserver", banner:banner );
set_mandatory_key( key:"Embedthis-Appweb", regex:"Server: Embedthis-Appweb", banner:banner );
set_mandatory_key( key:"Indy", regex:"Server: Indy", banner:banner );
set_mandatory_key( key:"TinyServer", regex:"Server: TinyServer", banner:banner );
set_mandatory_key( key:"ALLPLAYER-DLNA", regex:"Server: ALLPLAYER-DLNA", banner:banner );
set_mandatory_key( key:"TVMOBiLi", regex:"TVMOBiLi UPnP Server", banner:banner );
set_mandatory_key( key:"SpecView", regex:"SpecView", banner:banner );
set_mandatory_key( key:"Mathopd", regex:"Server: Mathopd", banner:banner );
set_mandatory_key( key:"Sockso", regex:"Server: Sockso", banner:banner );
set_mandatory_key( key:"SentinelKeysServer", regex:"Server: SentinelKeysServer", banner:banner );
set_mandatory_key( key:"fexsrv", regex:"Server: fexsrv", banner:banner );
set_mandatory_key( key:"Pi3Web", regex:"Pi3Web", banner:banner );
set_mandatory_key( key:"NetDecision-HTTP-Server", regex:"Server: NetDecision-HTTP-Server", banner:banner );
set_mandatory_key( key:"Asterisk", regex:"Server: Asterisk", banner:banner );
set_mandatory_key( key:"PMSoftware-SWS", regex:"Server: PMSoftware-SWS", banner:banner );
set_mandatory_key( key:"lighttpd", regex:"Server: lighttpd", banner:banner );
set_mandatory_key( key:"Null_httpd", regex:"Server: Null httpd", banner:banner );
set_mandatory_key( key:"TVersity_Media_Server", regex:"TVersity Media Server", banner:banner );
set_mandatory_key( key:"WR841N", regex:"WR841N", banner:banner );
set_mandatory_key( key:"IOServer", regex:"Server: IOServer", banner:banner );
set_mandatory_key( key:"Kerio_WinRoute", regex:"Server: Kerio WinRoute Firewall", banner:banner );
set_mandatory_key( key:"webcam_7_xp", regex:"Server: (webcam 7|webcamXP)", banner:banner );
set_mandatory_key( key:"nginx", regex:"Server: nginx", banner:banner );
set_mandatory_key( key:"WindRiver-WebServer", regex:"WindRiver-WebServer", banner:banner );
set_mandatory_key( key:"MobileWebServer", regex:"Server: MobileWebServer", banner:banner );
set_mandatory_key( key:"MPC-HC", regex:"Server: MPC-HC WebServer", banner:banner );
set_mandatory_key( key:"EAServer", regex:"EAServer", banner:banner );
set_mandatory_key( key:"Rapid_Logic", regex:"Server: Rapid Logic", banner:banner );
set_mandatory_key( key:"Aastra_6753i", regex:'Basic realm="Aastra 6753i"');
set_mandatory_key( key:"Light_HTTPd", regex:"Light HTTPd", banner:banner );
set_mandatory_key( key:"WebServer_IPCamera_Logo", regex:"Server: WebServer\(IPCamera_Logo\)", banner:banner );
set_mandatory_key( key:"KNet", regex:"Server: KNet", banner:banner );
set_mandatory_key( key:"netcam", regex:'Basic realm="netcam"');
set_mandatory_key( key:"DSL_Router", regex:'WWW-Authenticate: Basic realm="DSL Router"');
set_mandatory_key( key:"EA2700", regex:"EA2700", banner:banner );
set_mandatory_key( key:"TELES_AG", regex:"Server: TELES AG", banner:banner );
set_mandatory_key( key:"Z-World_Rabbit", regex:"Server: Z-World Rabbit", banner:banner );
set_mandatory_key( key:"Nero-MediaHome", regex:"Nero-MediaHome", banner:banner );
set_mandatory_key( key:"micro_httpd", regex:"Server: micro_httpd", banner:banner );
set_mandatory_key( key:"Monitorix", regex:"Monitorix", banner:banner );
set_mandatory_key( key:"Apache_SVN", regex:"Server: Apache.* SVN", banner:banner );
set_mandatory_key( key:"RT-Device", regex:'Basic realm="RT-');
set_mandatory_key( key:"ADSL_MODEM", regex:'Basic realm="ADSL Modem"');
set_mandatory_key( key:"Nucleus", regex:"Server: Nucleus", banner:banner );
set_mandatory_key( key:"RT-N10E", regex:'Basic realm="RT-N10E"');
set_mandatory_key( key:"RomPager", regex:"Server: RomPager", banner:banner );
set_mandatory_key( key:"thttpd", regex:"Server: thttpd", banner:banner );
set_mandatory_key( key:"NETGEAR_DGN", regex:'Basic realm="NETGEAR DGN');
set_mandatory_key( key:"Mbedthis-Appweb", regex:"Server: Mbedthis-Appweb", banner:banner );
set_mandatory_key( key:"MoxaHttp", regex:"Server: MoxaHttp", banner:banner );
set_mandatory_key( key:"Web_Server", regex:"Server: Web Server", banner:banner );
set_mandatory_key( key:"thttpd-alphanetworks", regex:"thttpd-alphanetworks", banner:banner );
set_mandatory_key( key:"WNR1000", regex:"NETGEAR WNR1000", banner:banner );
set_mandatory_key( key:"http_server", regex:"Server: http server", banner:banner );
set_mandatory_key( key:"Avtech", regex:"Server:.*Avtech", banner:banner );
set_mandatory_key( key:"Embedded_HTTP_Server", regex:"Server: Embedded HTTP Server", banner:banner );
set_mandatory_key( key:"sdk_for_upnp", regex:"sdk for upnp", banner:banner );
set_mandatory_key( key:"DIR-645", regex:"DIR-645", banner:banner );
set_mandatory_key( key:"Brickcom", regex:"Brickcom", banner:banner );
set_mandatory_key( key:"TD-W8951ND", regex:' Basic realm="TD-W8951ND"');
set_mandatory_key( key:"Resin", regex:"Server: Resin", banner:banner );
set_mandatory_key( key:"Aspen", regex:"Server: Aspen", banner:banner );
set_mandatory_key( key:"miniupnp", regex:"miniupnp", banner:banner );
set_mandatory_key( key:"DCS-9", regex:'realm="DCS-9');
set_mandatory_key( key:"Cross_Web_Server", regex:"Server: Cross Web Server", banner:banner );
set_mandatory_key( key:"EverFocus", regex:'realm="(EPARA|EPHD|ECOR)[^"]+"');
set_mandatory_key( key:"mini_httpd", regex:"Server: mini_httpd", banner:banner );
set_mandatory_key( key:"SAP", regex:"server: sap.*", banner:banner );
set_mandatory_key( key:"DIR-6_3_00", regex:"DIR-[63]00", banner:banner );
set_mandatory_key( key:"MyNetN679", regex:"MyNetN[6|7|9]", banner:banner );
set_mandatory_key( key:"DeWeS", regex:"Server: DeWeS", banner:banner );
set_mandatory_key( key:"Netwave_IP_Camera", regex:"Netwave IP Camera", banner:banner );
set_mandatory_key( key:"CIMPLICITY", regex:"Server: CIMPLICITY", banner:banner );
set_mandatory_key( key:"Jetty_EAServer", regex:"Server: Jetty\(EAServer", banner:banner );
set_mandatory_key( key:"intrasrv", regex:"Server: intrasrv", banner:banner );
set_mandatory_key( key:"IQhttp", regex:"Server: IQhttp", banner:banner );
set_mandatory_key( key:"cowboy", regex:"server: cowboy", banner:banner );
set_mandatory_key( key:"Raid_Console", regex:'realm="Raid Console"');
set_mandatory_key( key:"HyNetOS", regex:"HyNetOS", banner:banner );
set_mandatory_key( key:"dcs-lig-httpd", regex:"Server: dcs-lig-httpd", banner:banner );
set_mandatory_key( key:"PRN2001", regex:'Basic realm="PRN2001"');
set_mandatory_key( key:"ZK_Web_Server", regex:"Server: ZK Web Server", banner:banner );
set_mandatory_key( key:"ZXV10_W300", regex:'Basic realm="ZXV10 W300"');
set_mandatory_key( key:"Saia_PCD", regex:"Server: Saia PCD", banner:banner );
set_mandatory_key( key:"Arrakis", regex:"Server: Arrakis", banner:banner );
set_mandatory_key( key:"Mini_web_server", regex:"Server: Mini web server", banner:banner );
set_mandatory_key( key:"SOAPpy", regex:"SOAPpy", banner:banner );
set_mandatory_key( key:"DCS-2103", regex:'Basic realm="DCS-2103"');
set_mandatory_key( key:"WNR1000v3", regex:"NETGEAR WNR1000v3", banner:banner );
set_mandatory_key( key:"SIP-T38G", regex:'Basic realm="Gigabit Color IP Phone SIP-T38G"');
set_mandatory_key( key:"SnIP", regex:'Basic realm="SnIP');
set_mandatory_key( key:"GeoHttpServer", regex:"Server: GeoHttpServer", banner:banner );
set_mandatory_key( key:"Diva_HTTP", regex:"Server: Diva HTTP Plugin", banner:banner );
set_mandatory_key( key:"BlueDragon", regex:"BlueDragon Server", banner:banner );
set_mandatory_key( key:"SonicWALL", regex:"Server: SonicWALL", banner:banner );
set_mandatory_key( key:"Microsoft-HTTPAPI", regex:"Microsoft-HTTPAPI", banner:banner );
set_mandatory_key( key:"efmws", regex:"Server: Easy File Management Web Server", banner:banner );
set_mandatory_key( key:"Polycom_SoundPoint", regex:"erver: Polycom SoundPoint IP", banner:banner );
set_mandatory_key( key:"surgeftp", regex:'Basic realm="surgeftp');
set_mandatory_key( key:"SkyIPCam", regex:'Basic realm="SkyIPCam"');
set_mandatory_key( key:"RT-G32", regex:'Basic realm="RT-G32"');
set_mandatory_key( key:"Router_Webserver", regex:"Server: Router Webserver", banner:banner );
set_mandatory_key( key:"ExaGrid", regex:"Server: ExaGrid", banner:banner );
set_mandatory_key( key:"DSL-N55U", regex:'Basic realm="DSL-N55U');
set_mandatory_key( key:"JAWSJAWS", regex:"Server: JAWS", banner:banner );
set_mandatory_key( key:"NETGEAR", regex:'Basic realm="NETGEAR');
set_mandatory_key( key:"JVC_API", regex:"Server: JVC.*API Server", banner:banner );
set_mandatory_key( key:"ETag", regex:"ETag:", banner:banner );
set_mandatory_key( key:"BarracudaHTTP", regex:"Server: BarracudaHTTP", banner:banner );
set_mandatory_key( key:"AntServer", regex:"Server: AntServer", banner:banner );
set_mandatory_key( key:"CompaqHTTPServer", regex:"Server: CompaqHTTPServer", banner:banner );
set_mandatory_key( key:"FlashCom", regex:"erver: FlashCom", banner:banner );
set_mandatory_key( key:"Simple-Server", regex:"erver: Simple-Server", banner:banner );
set_mandatory_key( key:"mod_jk", regex:"mod_jk", banner:banner );
set_mandatory_key( key:"ATS", regex:"Server: ATS", banner:banner );
set_mandatory_key( key:"iTunes", regex:"DAAP-Server: iTunes", banner:banner );
set_mandatory_key( key:"BCReport", regex:"BCReport", banner:banner );
set_mandatory_key( key:"CouchDB", regex:"Server: CouchDB", banner:banner );
set_mandatory_key( key:"KACE-Appliance", regex:"X-(Dell)?KACE-Appliance:", banner:banner );
set_mandatory_key( key:"SMC6128L2", regex:'Basic realm="SMC6128L2');
set_mandatory_key( key:"kibana", regex:"kbn-name: kibana", banner:banner );
set_mandatory_key( key:"SiemensGigaset-Server", regex:"Server: SiemensGigaset-Server", banner:banner );
set_mandatory_key( key:"Grandstream_GXP", regex:"Server: Grandstream GXP", banner:banner );
set_mandatory_key( key:"h2o", regex:"Server: h2o", banner:banner );
set_mandatory_key( key:"HHVM", regex:"X-Powered-By: HHVM", banner:banner );
set_mandatory_key( key:"HFS", regex:"erver: HFS", banner:banner );
set_mandatory_key( key:"BigFixHTTPServer", regex:"Server: BigFixHTTPServer", banner:banner );
set_mandatory_key( key:"IBM_WebSphere", regex:"Server: IBM WebSphere", banner:banner );
set_mandatory_key( key:"Ingate-SIParator", regex:"erver: Ingate-SIParator", banner:banner );
set_mandatory_key( key:"IAMT", regex:"Server: Intel\(R\) Active Management Technology", banner:banner );
set_mandatory_key( key:"KCEWS", regex:"Server: Kerio Control Embedded Web Server", banner:banner );
set_mandatory_key( key:"Loxone", regex:"Server: Loxone", banner:banner );
set_mandatory_key( key:"MatrixSSL", regex:"Server: .*MatrixSSL", banner:banner );
set_mandatory_key( key:"McAfee_Web_Gateway", regex:"McAfee Web Gateway", banner:banner );
set_mandatory_key( key:"NaviCOPA", regex:"NaviCOPA", banner:banner );
set_mandatory_key( key:"wnr2000", regex:'Basic realm="NETGEAR wnr2000');
set_mandatory_key( key:"nghttpx", regex:"Server: nghttpx", banner:banner );
set_mandatory_key( key:"Norman_Security", regex:"Server: Norman Security", banner:banner );
set_mandatory_key( key:"NullLogic_Groupware", regex:"NullLogic Groupware", banner:banner );
set_mandatory_key( key:"OpenSSL", regex:"OpenSSL", banner:banner );
set_mandatory_key( key:"OrientDB", regex:"OrientDB Server", banner:banner );
set_mandatory_key( key:"PanWeb", regex:"Server: PanWeb Server", banner:banner );
set_mandatory_key( key:"powerfolder", regex:"powerfolder", banner:banner );
set_mandatory_key( key:"PRTG", regex:"Server: PRTG", banner:banner );
set_mandatory_key( key:"Python", regex:"Python", banner:banner );
set_mandatory_key( key:"JBoss-EAP", regex:"JBoss-EAP", banner:banner );
set_mandatory_key( key:"MochiWeb", regex:"MochiWeb", banner:banner );
set_mandatory_key( key:"Schneider-WEB", regex:"Server: Schneider-WEB", banner:banner );
set_mandatory_key( key:"Shareaza", regex:"Shareaza", banner:banner );
set_mandatory_key( key:"WebBox", regex:"Server: WebBox", banner:banner );
set_mandatory_key( key:"ILOM-Web-Server", regex:"Server: (Sun|Oracle)-ILOM-Web-Server", banner:banner );
set_mandatory_key( key:"Apache-Coyote", regex:"Server: Apache-Coyote", banner:banner );
set_mandatory_key( key:"VLC_stream", regex:'Basic realm="VLC stream"');
set_mandatory_key( key:"WSO2_Carbon", regex:"Server: WSO2 Carbon Server", banner:banner );
set_mandatory_key( key:"WSO2_SOA", regex:"Server: WSO2 SOA Enablement Server", banner:banner );
set_mandatory_key( key:"Xerver", regex:"Server: Xerver", banner:banner );
set_mandatory_key( key:"MLDonkey", regex:"MLDonkey", banner:banner );
set_mandatory_key( key:"myCIO", regex:"myCIO", banner:banner );
set_mandatory_key( key:"ntop", regex:"Server: ntop", banner:banner );
set_mandatory_key( key:"RemotelyAnywhere", regex:"Server: *RemotelyAnywhere", banner:banner );
set_mandatory_key( key:"Sami_HTTP", regex:"Server:.*Sami HTTP Server", banner:banner );
set_mandatory_key( key:"MailEnable", regex:"Server: .*MailEnable", banner:banner );
set_mandatory_key( key:"PHP", regex:"PHP", banner:banner );
set_mandatory_key( key:"IIS", regex:"IIS", banner:banner );
set_mandatory_key( key:"ZyXEL-RomPager", regex:"ZyXEL-RomPager", banner:banner );
set_mandatory_key( key:"Allegro", regex:"Allegro", banner:banner );
set_mandatory_key( key:"X-Kazaa-Username", regex:"X-Kazaa-Username", banner:banner );
set_mandatory_key( key:"icecast", regex:"icecast", banner:banner );
set_mandatory_key( key:"vqServer", regex:"Server: vqServer", banner:banner );
set_mandatory_key( key:"dwhttp", regex:"dwhttp", banner:banner );
set_mandatory_key( key:"ATR-HTTP", regex:"Server: ATR-HTTP-Server", banner:banner );
set_mandatory_key( key:"JRun", regex:"JRun", banner:banner );
set_mandatory_key( key:"WRT54G", regex:'realm="WRT54G"');
set_mandatory_key( key:"Ultraseek", regex:"Server: Ultraseek", banner:banner );
set_mandatory_key( key:"Domino", regex:"Domino", banner:banner );
set_mandatory_key( key:"Roxen", regex:"Roxen", banner:banner );
set_mandatory_key( key:"OracleAS-Web-Cache", regex:"OracleAS-Web-Cache", banner:banner );
set_mandatory_key( key:"WDaemon", regex:"Server: WDaemon", banner:banner );
set_mandatory_key( key:"Oracle", regex:"Oracle", banner:banner );
set_mandatory_key( key:"Enhydra", regex:"Enhydra", banner:banner );
set_mandatory_key( key:"OmniHTTPd", regex:"OmniHTTPd", banner:banner );
set_mandatory_key( key:"Statistics_Server", regex:"Server: Statistics Server", banner:banner );
set_mandatory_key( key:"mod_python", regex:"mod_python", banner:banner );
set_mandatory_key( key:"Xeneo", regex:"Xeneo", banner:banner );
set_mandatory_key( key:"RemotelyAnywhere", regex:"RemotelyAnywhere", banner:banner );
set_mandatory_key( key:"4D_WebSTAR", regex:"^Server: 4D_WebSTAR", banner:banner );
set_mandatory_key( key:"limewire", regex:"limewire", banner:banner );
set_mandatory_key( key:"TinyWeb", regex:"Server:.*TinyWeb", banner:banner );
set_mandatory_key( key:"BadBlue", regex:"BadBlue", banner:banner );
set_mandatory_key( key:"Jetadmin", regex:"HP Web Jetadmin", banner:banner );
set_mandatory_key( key:"VisualRoute", regex:"Server: VisualRoute", banner:banner );
set_mandatory_key( key:"SimpleServer", regex:"SimpleServer", banner:banner );
set_mandatory_key( key:"LocalWEB2000", regex:"Server: .*LocalWEB2000", banner:banner );
set_mandatory_key( key:"LabVIEW", regex:"Server: LabVIEW", banner:banner );
set_mandatory_key( key:"shoutcast", regex:"shoutcast", banner:banner );
set_mandatory_key( key:"+WN", regex:"Server: +WN", banner:banner );
set_mandatory_key( key:"Lotus", regex:"Lotus", banner:banner );
set_mandatory_key( key:"Netscape_iPlanet", regex:"(Netscape|iPlanet)", banner:banner );
set_mandatory_key( key:"linksys", regex:"linksys", banner:banner );
set_mandatory_key( key:"oaohi", regex:"Oracle Applications One-Hour Install", banner:banner );
set_mandatory_key( key:"Web_Server_4D", regex:"Web_Server_4D", banner:banner );
set_mandatory_key( key:"eMule", regex:"eMule", banner:banner );
set_mandatory_key( key:"Novell_Netware", regex:"(Novell|Netware)", banner:banner );
set_mandatory_key( key:"W4E", regex:"WebServer 4 Everyone", banner:banner );
set_mandatory_key( key:"vncviewer_jc", regex:"vncviewer\.(jar|class)", banner:banner );
set_mandatory_key( key:"MagnoWare", regex:"Server: MagnoWare", banner:banner );
set_mandatory_key( key:"ELOG_HTTP", regex:"Server: ELOG HTTP", banner:banner );
set_mandatory_key( key:"RTC", regex:"Server: RTC", banner:banner );
set_mandatory_key( key:"ZendServer", regex:"ZendServer", banner:banner );
set_mandatory_key( key:"SWS", regex:"Server: SWS-", banner:banner );
set_mandatory_key( key:"RealVNC", regex:"RealVNC", banner:banner );
set_mandatory_key( key:"PST10", regex:"Server: PST10 WebServer", banner:banner );
set_mandatory_key( key:"Anti-Web", regex:"Server: Anti-Web", banner:banner );
set_mandatory_key( key:"Unspecified-UPnP", regex:"Server: Unspecified, UPnP", banner:banner );
set_mandatory_key( key:"debut", regex:"Server: debut", banner:banner );
set_mandatory_key( key:"libsoup", regex:"Server: (soup-transcode-proxy )?libsoup", banner:banner );
set_mandatory_key( key:"spidercontrol-scada", regex:"Server: SCADA.*(powered by SpiderControl TM)", banner:banner );
set_mandatory_key( key:"StorageGRID", regex:"Server: StorageGRID", banner:banner );
set_mandatory_key( key:"NetApp", regex: "Server: (NetApp|Data ONTAP)", banner:banner );
set_mandatory_key( key:"App-webs", regex: "Server: App-webs", banner:banner );
set_mandatory_key( key:"Kannel", regex: "Server: Kannel", banner:banner );
set_mandatory_key( key:"akka", regex: "Server: akka-http", banner:banner );
set_mandatory_key( key:"voipnow", regex: "Server: voipnow", banner:banner );
set_mandatory_key( key:"D-LinkDNS", regex: "Server: (lighttpd/|GoAhead-Webs)", banner:banner );
set_mandatory_key( key:"D-LinkDIR", regex: "Server: (Linux, ((HTTP/1\.1)|(WEBACCESS/1\.0)), DIR|Mathopd|WebServer)", banner:banner );
set_mandatory_key( key:"D-LinkDSL", regex:"Server: (Boa|micro_httpd|Linux|RomPager)", banner:banner ); # For gb_dlink_dsl_detect.nasl
set_mandatory_key( key:"D-LinkDWR", regex:"Server: (GoAhead-Webs|server|Alpha_webserv|WebServer)", banner:banner ); # For gb_dlink_dwr_detect.nasl
set_mandatory_key( key:"Cohu", regex: "Server: Cohu Camera", banner:banner );
set_mandatory_key( key:"HTTPserv", regex: "Server: .*HTTPserv:", banner:banner );
set_mandatory_key( key:"ABwww", regex: "Server: A-B WWW", banner:banner );
set_mandatory_key( key:"yawcam", regex: "Server: yawcam", banner:banner );
set_mandatory_key( key:"JetBrainsIDEs", regex: "server: (PyCharm|WebStorm|CLion|DataGrip|IntelliJ|JetBrains|JetBrains|jetBrains|RubyMine)", banner:banner );
set_mandatory_key( key:"tplink_httpd", regex: "Server: TP-LINK HTTPD", banner:banner );
set_mandatory_key( key:"monit", regex: "Server: monit", banner:banner );
set_mandatory_key( key:"CirCarLife", regex: "Server: CirCarLife Scada", banner:banner );
set_mandatory_key( key:"mt-daapd", regex: "Server: mt-daapd", banner:banner );
set_mandatory_key( key:"Promotic", regex: "Server: pm", banner:banner );
set_mandatory_key( key:"ServersCheck_Monitoring_Server", regex: "Server: ServersCheck_Monitoring_Server", banner:banner );
set_mandatory_key( key:"IWB", regex: "Server: IWB Web-Server", banner:banner );
set_mandatory_key( key:"Mongoose", regex: "Server: Mongoose", banner:banner );
set_mandatory_key( key:"LogitechMediaServer", regex: "Server: Logitech Media Server", banner:banner );
set_mandatory_key( key:"HttpServer", regex: "Server: HttpServer", banner:banner );
set_mandatory_key( key:"coturn", regex: "Server: Coturn", banner:banner );
set_mandatory_key( key:"WebLogic", regex: "^Server:.*WebLogic", banner:banner );
set_mandatory_key( key:"QuickTime_Darwin", regex: "(QuickTime|DSS)", banner:banner );
set_mandatory_key( key:"mini_httpd_or_thttpd", regex: "^Server: (mini_|t)httpd", banner:banner );
set_mandatory_key( key:"Oracle-Application-or-HTTP-Server", regex:"Oracle-(Application|HTTP)-Server", banner:banner );

exit( 0 );
