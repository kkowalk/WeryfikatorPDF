//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/x/cosh"
	"github.com/rodrigocfd/windigo/x/winsh"
)

func init() { runtime.LockOSThread() } // Win32 GUI must stay on one OS thread

// launchedFromExplorer: a double-click or drag-and-drop gives the process its own
// console; started from cmd/PowerShell the console is shared with the shell.
func launchedFromExplorer() bool {
	var pids [2]uint32
	n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList").
		Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// enableVisualStyles activates Common Controls v6 without an embedded manifest.
// ponytail: temp manifest file; an embedded manifest resource would make this unnecessary.
func enableVisualStyles() {
	f, err := os.CreateTemp("", "weryfikator-*.manifest")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	f.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><dependency><dependentAssembly>
<assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
</dependentAssembly></dependency></assembly>`)
	f.Close()
	var ac win.ACTCTX
	ac.SetCbSize()
	ac.LpSource, _ = syscall.UTF16PtrFromString(f.Name())
	// windigo v0.2.7 looks up "CreateActCtx", which kernel32 exports only as CreateActCtxW.
	k32 := syscall.NewLazyDLL("kernel32.dll")
	h, _, _ := k32.NewProc("CreateActCtxW").Call(uintptr(unsafe.Pointer(&ac)))
	if h != ^uintptr(0) { // INVALID_HANDLE_VALUE
		var cookie uintptr
		k32.NewProc("ActivateActCtx").Call(h, uintptr(unsafe.Pointer(&cookie))) // active for the process lifetime
	}
}

type gui struct {
	wnd                                       *ui.Main
	lv                                        *ui.ListView
	btnFiles, btnDir, btnRemove, btnClear     *ui.Button
	btnOut, btnOpenDir, btnOpenReport, btnRun *ui.Button
	chkAsk, chkOffline                        *ui.CheckBox
	txtOut                                    *ui.Edit
	prog                                      *ui.ProgressBar
	lblProg                                   *ui.Static
	files                                     []string
	outDir, lastOut                           string
	reports                                   []*fileReport // of the last run, by list index
	running                                   bool
}

const defaultOutText = "(domyślnie: nowy folder obok pierwszego pliku)"

func runGUI(initial []string) int {
	win.FreeConsole() // hide the console window Explorer opened for us
	enableVisualStyles()
	win.CoInitializeEx(co.COINIT_APARTMENTTHREADED | co.COINIT_DISABLE_OLE1DDE)
	defer win.CoUninitialize()

	g := &gui{}
	g.wnd = ui.NewMain(ui.OptsMain().
		Title("Weryfikator podpisów PDF " + version).
		Size(ui.Dpi(780, 540)).
		Style(co.WS_CAPTION | co.WS_SYSMENU | co.WS_CLIPCHILDREN | co.WS_BORDER | co.WS_VISIBLE |
			co.WS_MINIMIZEBOX | co.WS_MAXIMIZEBOX | co.WS_SIZEBOX).
		ExStyle(co.WS_EX_ACCEPTFILES).
		Center(true))
	w := g.wnd
	btn := func(text string, x, y, width int, lay ui.LAY) *ui.Button {
		return ui.NewButton(w, ui.OptsButton().Text(text).Position(ui.Dpi(x, y)).Width(ui.DpiX(width)).Height(ui.DpiY(26)).Layout(lay))
	}

	ui.NewStatic(w, ui.OptsStatic().Text("Przeciągnij pliki PDF lub foldery na to okno albo użyj przycisków.").Position(ui.Dpi(10, 12)))
	g.btnFiles = btn("Dodaj pliki…", 10, 36, 110, ui.LAY_HOLD_HOLD)
	g.btnDir = btn("Dodaj folder…", 126, 36, 110, ui.LAY_HOLD_HOLD)
	g.btnRemove = btn("Usuń zaznaczone", 242, 36, 130, ui.LAY_HOLD_HOLD)
	g.btnClear = btn("Wyczyść listę", 378, 36, 110, ui.LAY_HOLD_HOLD)
	g.lv = ui.NewListView(w, ui.OptsListView().
		Position(ui.Dpi(10, 70)).Size(ui.Dpi(760, 290)).Layout(ui.LAY_RESIZE_RESIZE).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_GRIDLINES).
		Column("Plik", ui.DpiX(230)).Column("Podpisy", ui.DpiX(60)).
		Column("Stan", ui.DpiX(100)).Column("Wynik", ui.DpiX(345)))
	g.chkAsk = ui.NewCheckBox(w, ui.OptsCheckBox().Text("Pytaj o datę każdego podpisu").Position(ui.Dpi(10, 372)).Layout(ui.LAY_HOLD_MOVE))
	g.chkOffline = ui.NewCheckBox(w, ui.OptsCheckBox().Text("Tryb offline (bez sieci)").Position(ui.Dpi(260, 372)).Layout(ui.LAY_HOLD_MOVE))
	ui.NewStatic(w, ui.OptsStatic().Text("Katalog raportu:").Position(ui.Dpi(10, 405)).Layout(ui.LAY_HOLD_MOVE))
	g.txtOut = ui.NewEdit(w, ui.OptsEdit().Text(defaultOutText).Position(ui.Dpi(110, 401)).Width(ui.DpiX(544)).
		CtrlStyle(co.ES_AUTOHSCROLL|co.ES_READONLY).Layout(ui.LAY_RESIZE_MOVE))
	g.btnOut = btn("Zmień…", 660, 400, 110, ui.LAY_MOVE_MOVE)
	g.prog = ui.NewProgressBar(w, ui.OptsProgressBar().Position(ui.Dpi(10, 444)).Size(ui.Dpi(644, 16)).Layout(ui.LAY_RESIZE_MOVE))
	g.lblProg = ui.NewStatic(w, ui.OptsStatic().Text("").Position(ui.Dpi(660, 444)).Size(ui.Dpi(110, 18)).Layout(ui.LAY_MOVE_MOVE))
	g.btnOpenDir = btn("Otwórz folder raportu", 370, 474, 160, ui.LAY_MOVE_MOVE)
	g.btnOpenReport = btn("Otwórz raport", 536, 474, 118, ui.LAY_MOVE_MOVE)
	g.btnRun = btn("Weryfikuj", 660, 474, 110, ui.LAY_MOVE_MOVE)
	ui.NewStatusBar(w, ui.OptsStatusBar().FlexPart(1, "Dokumenty nie są wysyłane. Sieć: tylko listy zaufanych usług UE oraz CRL/OCSP (szczegóły: PRIVACY.md)."))
	g.lv.On().NmDblClk(func(p *win.NMITEMACTIVATE) { // open the report of the clicked file
		if i := int(p.IItem); i >= 0 && i < len(g.reports) && g.reports[i] != nil {
			openBrowser(filepath.Join(g.lastOut, g.reports[i].Report))
		}
	})

	w.On().WmCreate(func(ui.WmCreate) int {
		g.add(initial)
		return 0
	})
	w.On().WmDropFiles(func(p ui.WmDropFiles) {
		paths, _ := p.HDrop().DragQueryFile()
		p.HDrop().DragFinish()
		if !g.running {
			g.add(paths)
		}
	})
	g.btnFiles.On().BnClicked(func() { g.add(g.pick(false, true)) })
	g.btnDir.On().BnClicked(func() { g.add(g.pick(true, true)) })
	g.btnRemove.On().BnClicked(func() {
		var keep []string
		for i, it := range g.lv.Items() {
			if !it.IsSelected() {
				keep = append(keep, g.files[i])
			}
		}
		g.files, g.reports = nil, nil
		g.lv.DeleteAllItems()
		g.add(keep)
	})
	g.btnClear.On().BnClicked(func() {
		g.files, g.reports = nil, nil
		g.lv.DeleteAllItems()
	})
	g.btnOut.On().BnClicked(func() {
		if p := g.pick(true, false); len(p) == 1 {
			g.outDir = p[0]
			g.txtOut.SetText(p[0])
		}
	})
	g.btnOpenReport.On().BnClicked(func() {
		if g.lastOut == "" {
			g.msg("Najpierw uruchom weryfikację.", co.MB_ICONINFORMATION)
			return
		}
		openBrowser(filepath.Join(g.lastOut, "index.html"))
	})
	g.btnOpenDir.On().BnClicked(func() {
		if g.lastOut == "" {
			g.msg("Najpierw uruchom weryfikację.", co.MB_ICONINFORMATION)
			return
		}
		exec.Command("explorer.exe", g.lastOut).Start()
	})
	g.btnRun.On().BnClicked(g.run)
	return w.RunAsMain()
}

func (g *gui) msg(text string, icon co.MB) {
	g.wnd.Hwnd().MessageBox(text, "Weryfikator podpisów PDF", icon)
}

// add appends PDF files (folders are expanded), skipping duplicates.
func (g *gui) add(paths []string) {
	have := map[string]bool{}
	for _, f := range g.files {
		have[f] = true
	}
	for _, f := range collect(paths) {
		if abs, err := filepath.Abs(f); err == nil {
			f = abs
		}
		if !have[f] {
			have[f] = true
			g.files = append(g.files, f)
			g.lv.AddItem(filepath.Base(f), "", "Oczekuje", "")
		}
	}
}

// pick shows the system file/folder dialog.
func (g *gui) pick(folders, multi bool) []string {
	rel := win.NewOleReleaser()
	defer rel.Release()
	var fod *winsh.IFileOpenDialog
	if err := win.CoCreateInstance(rel, &cosh.CLSID_FileOpenDialog, nil, co.CLSCTX_INPROC_SERVER, &fod); err != nil {
		return nil
	}
	opts, _ := fod.GetOptions()
	opts |= cosh.FOS_FORCEFILESYSTEM
	if multi {
		opts |= cosh.FOS_ALLOWMULTISELECT
	}
	if folders {
		opts |= cosh.FOS_PICKFOLDERS
	} else {
		fod.SetFileTypes([]winsh.COMDLG_FILTERSPEC{{Name: "Pliki PDF", Spec: "*.pdf"}})
	}
	fod.SetOptions(opts)
	if ok, _ := fod.Show(g.wnd.Hwnd()); !ok {
		return nil
	}
	arr, err := fod.GetResults(rel)
	if err != nil {
		return nil
	}
	paths, _ := arr.EnumDisplayNames(cosh.SIGDN_FILESYSPATH)
	return paths
}

func (g *gui) setRunning(r bool) {
	g.running = r
	for _, b := range []*ui.Button{g.btnFiles, g.btnDir, g.btnRemove, g.btnClear, g.btnOut, g.btnRun} {
		b.Hwnd().EnableWindow(!r)
	}
	g.chkAsk.Hwnd().EnableWindow(!r)
	g.chkOffline.Hwnd().EnableWindow(!r)
}

func (g *gui) run() {
	if len(g.files) == 0 {
		g.msg("Dodaj pliki PDF do weryfikacji.", co.MB_ICONINFORMATION)
		return
	}
	files := append([]string(nil), g.files...)
	out := g.outDir
	if out == "" {
		out = defaultOut(files, files[0])
	}
	e := newEnv(out, g.chkOffline.IsChecked())
	if g.chkAsk.IsChecked() {
		keepAsking := true
		e.ask = func(fname string, n int, signer string, cands []dateCand) dateCand {
			if !keepAsking {
				return firstOrZero(cands)
			}
			var d dateCand
			g.wnd.UiThread(func() { d, keepAsking = g.dateDialog(fname, n, signer, cands) })
			return d
		}
	}
	for i := range files {
		g.lv.Item(i).SetText(1, "").SetText(2, "Oczekuje").SetText(3, "")
	}
	g.prog.SetRange(0, len(files)).SetPos(0)
	g.lastOut, g.reports = out, make([]*fileReport, len(files))
	g.setRunning(true)

	go func() {
		_, err := e.verifyAll(files, out, func(i int, fr *fileReport) {
			g.wnd.UiThread(func() {
				it := g.lv.Item(i)
				if fr == nil {
					it.SetText(2, "Analiza…")
					g.lblProg.Hwnd().SetWindowText(fmt.Sprintf("%d z %d", i, len(files)))
					return
				}
				g.reports[i] = fr
				it.SetText(1, strconv.Itoa(countSigs(fr))).SetText(2, "Gotowe").SetText(3, summary(fr))
				g.prog.SetPos(i + 1)
				g.lblProg.Hwnd().SetWindowText(fmt.Sprintf("%d z %d", i+1, len(files)))
			})
		})
		g.wnd.UiThread(func() {
			g.setRunning(false)
			if err != nil {
				g.msg(err.Error(), co.MB_ICONERROR)
			}
		})
	}()
}

func countSigs(fr *fileReport) int {
	n := 0
	for _, s := range fr.Sigs {
		if s.Kind == "Podpis" {
			n++
		}
	}
	return n
}

// summary: file verdict plus expiry/revocation notes, as in the summary report.
func summary(fr *fileReport) string {
	parts := []string{fr.Verdict}
	if fr.Error != "" {
		parts = append(parts, fr.Error)
	}
	for _, s := range fr.Sigs {
		for _, n := range s.Notes {
			parts = append(parts, fmt.Sprintf("#%d %s", s.N, n))
		}
	}
	return strings.Join(parts, " | ")
}

func firstOrZero(c []dateCand) dateCand {
	if len(c) > 0 {
		return c[0]
	}
	return dateCand{}
}

// dateDialog asks for the signing date; keepAsking=false after "Przyjmij dla wszystkich".
func (g *gui) dateDialog(fname string, n int, signer string, cands []dateCand) (d dateCand, keepAsking bool) {
	d, keepAsking = firstOrZero(cands), true
	y := 44 + 26*len(cands)
	dlg := ui.NewModal(g.wnd, ui.OptsModal().
		Title(fmt.Sprintf("Data podpisu — %s, podpis #%d", fname, n)).
		Size(ui.Dpi(560, y+110)))
	ui.NewStatic(dlg, ui.OptsStatic().Text("Podpisujący: "+signer).Position(ui.Dpi(12, 12)))
	var radios []*ui.VarOptsRadioButton
	for i, c := range cands {
		radios = append(radios, ui.OptsRadioButton().Text(c.Shown+" — "+c.Source).
			Position(ui.Dpi(12, 40+26*i)).Size(ui.Dpi(536, 22)).Selected(i == 0))
	}
	radios = append(radios, ui.OptsRadioButton().Text("Inna data:").Position(ui.Dpi(12, y)).Size(ui.Dpi(90, 22)).Selected(len(cands) == 0))
	rg := ui.NewRadioGroup(dlg, radios...)
	def := time.Now()
	if len(cands) > 0 {
		def = cands[0].T
	}
	dp := ui.NewDateTimePicker(dlg, ui.OptsDateTimePicker().Position(ui.Dpi(108, y-2)).Size(ui.Dpi(130, 24)).
		CtrlStyle(co.DTS_SHORTDATECENTURYFORMAT).Value(def))
	tp := ui.NewDateTimePicker(dlg, ui.OptsDateTimePicker().Position(ui.Dpi(246, y-2)).Size(ui.Dpi(110, 24)).
		CtrlStyle(co.DTS_TIMEFORMAT).Value(def))
	ui.NewStatic(dlg, ui.OptsStatic().Text("Data podana ręcznie trafia do raportu jako oświadczenie użytkownika.").Position(ui.Dpi(12, y+34)))
	btnAll := ui.NewButton(dlg, ui.OptsButton().Text("Przyjmij dla wszystkich").Position(ui.Dpi(270, y+66)).Width(ui.DpiX(170)).Height(ui.DpiY(26)))
	btnOK := ui.NewButton(dlg, ui.OptsButton().Text("OK").Position(ui.Dpi(448, y+66)).Width(ui.DpiX(100)).Height(ui.DpiY(26)).CtrlStyle(co.BS_DEFPUSHBUTTON))

	closeDlg := func() { dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0) }
	btnOK.On().BnClicked(func() {
		if sel := rg.Selected(); sel != nil && sel.Index() < len(cands) {
			d = cands[sel.Index()]
		} else {
			day, clock := dp.Time(), tp.Time()
			d = manualDate(time.Date(day.Year(), day.Month(), day.Day(), clock.Hour(), clock.Minute(), clock.Second(), 0, time.Local))
		}
		closeDlg()
	})
	btnAll.On().BnClicked(func() {
		d, keepAsking = firstOrZero(cands), false
		closeDlg()
	})
	dlg.ShowModal()
	return d, keepAsking
}
