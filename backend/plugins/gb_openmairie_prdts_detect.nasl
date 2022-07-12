###############################################################################
# OpenVAS Vulnerability Test
#
# OpenMairie Products Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-20
#   - To detect some more products
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-21
#  - Updated to detect Opencatalogue product
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
  script_oid("1.3.6.1.4.1.25623.1.0.800779");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenMairie Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed OpenMairie products version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

openPort = get_http_port(default:80);
if (!can_host_php(port:openPort)) exit(0);

list = make_list_unique(
"/openmairie_annuaire", "/Openmairie_Annuaire",
"/openmairie_courrier","/Openmairie_Courrier",
"/openmairie_planning", "/Openmairie_Planning",
"/openmairie_presse", "/Openmairie_Presse",
"/openmairie_cominterne", "/Openmairie_Cominterne",
"/openmairie_foncier", "/Openmairie_Foncier",
"/openmairie_registreCIL", "/Openmairie_RegistreCIL",
"/openmairie_cimetiere", "/Openmairie_Cimetiere", "/", cgi_dirs(port:openPort));

foreach dir(list) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir , "/index.php"), port:openPort);

  if(">Open Annuaire&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Annuaire", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Annuaire", ver:tmp_version, base:"cpe:/a:openmairie:openannuaire:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if(">Open Courrier&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)([a-z]*)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Courrier", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Courrier", ver:tmp_version, base:"cpe:/a:openmairie:opencourrier:",
                              expr:"^([0-9.]+)", insloc:install);
     # exit(0);
    }
  }

  if("courrier" >< rcvRes)
  {
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Courrier", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Courrier", ver:tmp_version, base:"cpe:/a:openmairie:opencourrier:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if("presse" >< rcvRes)
  {
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Presse", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Presse", ver:tmp_version, base:"cpe:/a:openmairie:openpresse:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if(">Open Planning&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Planning", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Planning", ver:tmp_version, base:"cpe:/a:openmairie:openplanning:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if("Communication Interne" >< rcvRes)
  {
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_ComInterne", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open ComInterne", ver:tmp_version, base:"cpe:/a:openmairie:opencominterne:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if(">opencimetiere" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Cimetiere", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Cimetiere", ver:tmp_version, base:"cpe:/a:openmairie:opencimetiere:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }

  if(">Open Registre CIL&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Registre_CIL", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Registre CIL", ver:tmp_version, base:"cpe:/a:openmairie:openregistrecil:",
                              expr:"^([0-9.]+)", insloc:install);
     }
   }

  if(">openFoncier<" >< rcvRes || "Fonciere" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Foncier", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Foncier", ver:tmp_version, base:"cpe:/a:openmairie:openfoncier:",
                              expr:"^([0-9.]+)", insloc:install);
    }

    openVer = eregmatch(pattern:">version ((beta)?.?([0-9.]+))", string:rcvRes);
    openVer[1] = ereg_replace(pattern:" ", string:openVer[1], replace:".");
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Foncier", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Foncier", ver:tmp_version, base:"cpe:/a:openmairie:openfoncier:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }
}

foreach dir (make_list_unique("/openmairie_catalogue", "/Openmairie_Catalogue", cgi_dirs(port:openPort)))
{

  install = dir;
  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir , "/doc/catalogue.html"), port:openPort);
  rcvRes = http_keepalive_send_recv(port:openPort, data:sndReq);

  if("OPENCATALOGUE" >< rcvRes || "[Cc]atalogue" >< rcvRes)
  {
    rcvRes = http_get_cache(item:string(dir , "/index.php"), port:openPort);

    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      tmp_version = openVer[1] + " under " + install;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Catalogue", value:tmp_version);
      set_kb_item(name:"openmairie/products/detected", value:TRUE);

      register_and_report_cpe(app:"Open Catalogue", ver:tmp_version, base:"cpe:/a:openmairie:opencatalogue:",
                              expr:"^([0-9.]+)", insloc:install);
    }
  }
}
