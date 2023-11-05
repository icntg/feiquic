program project_feiquic;

{$mode objfpc}{$H+}
{$UNITPATH ../inc}
uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  {$IFDEF HASAMIGA}
  athreads,
  {$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, unitFormMain, UnitQuic,
  { you can add units after this }
  quiche;

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Scaled:=True;
  Application.Initialize;
  Application.CreateForm(TFormMainFeiquic, FormMainFeiquic);
  Application.Run;
end.

