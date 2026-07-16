"use client";

import { useState } from "react";
import { Search, ShieldCheck, ShieldAlert, Download, AlertTriangle, Info, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

// Tipos base para el veredicto
type VerdictStatus = "Seguro" | "Sospechoso" | "Malicioso";

interface ValidationMethod {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

interface AnalysisResult {
  url: string;
  verdict: VerdictStatus;
  riskScore: number;
  methods: ValidationMethod[];
}

// Base del API FastAPI (configurable via variable de entorno)
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function Home() {
  const [url, setUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Llama al backend de FastAPI y muestra el veredicto
  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsAnalyzing(true);
    setResult(null);
    setError(null);

    try {
      const resp = await fetch(`${API_URL}/api/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!resp.ok) {
        throw new Error(`El servidor respondio ${resp.status}`);
      }
      const data: AnalysisResult = await resp.json();
      setResult(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "No se pudo conectar con el servicio de analisis."
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Genera reporte PDF usando jsPDF
  const exportToPDF = () => {
    if (!result) return;
    
    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text("Reporte de Auditoría LinkSecure", 14, 22);
    
    doc.setFontSize(12);
    doc.text(`URL Analizada: ${result.url}`, 14, 32);
    doc.text(`Veredicto Final: ${result.verdict}`, 14, 40);
    doc.text(`Score de Riesgo: ${result.riskScore}/100`, 14, 48);
    doc.text(`Fecha de Análisis: ${new Date().toLocaleString()}`, 14, 56);

    const tableData = result.methods.map(m => [m.name, m.status.toUpperCase(), m.detail]);
    
    autoTable(doc, {
      startY: 64,
      head: [['Método de Validación', 'Estado', 'Detalle']],
      body: tableData,
    });

    doc.save(`LinkSecure_Report_${Date.now()}.pdf`);
  };

  // Helper para color de veredicto
  const getVerdictColor = (verdict: VerdictStatus) => {
    switch (verdict) {
      case "Seguro": return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
      case "Sospechoso": return "text-amber-500 bg-amber-500/10 border-amber-500/20";
      case "Malicioso": return "text-red-500 bg-red-500/10 border-red-500/20";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pass": return <CheckCircle2 className="w-5 h-5 text-emerald-500" />;
      case "warn": return <AlertTriangle className="w-5 h-5 text-amber-500" />;
      case "fail": return <XCircle className="w-5 h-5 text-red-500" />;
      default: return null;
    }
  };

  return (
    <main className="min-h-screen flex flex-col items-center py-20 px-4 md:px-8 relative overflow-hidden">
      {/* Elementos decorativos de fondo */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-primary/20 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-blue-600/10 blur-[120px] pointer-events-none" />

      {/* Header */}
      <div className="z-10 text-center mb-12 max-w-2xl">
        <div className="inline-flex items-center justify-center p-3 mb-4 rounded-2xl glass-panel">
          <ShieldCheck className="w-10 h-10 text-primary" />
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4 text-foreground">
          Link<span className="text-gradient">Secure</span>
        </h1>
        <p className="text-muted-foreground text-lg">
          Validación corporativa de enlaces y detección de amenazas en tiempo real.
        </p>
      </div>

      {/* Main Input Area */}
      <Card className="z-10 w-full max-w-3xl glass-panel border-0 shadow-2xl mb-8">
        <CardContent className="p-2">
          <form onSubmit={handleAnalyze} className="flex relative">
            <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-muted-foreground" />
            </div>
            <Input
              type="url"
              placeholder="Ingrese la URL para análisis de seguridad (ej. https://banco.com)"
              className="glass-input h-16 pl-12 pr-36 text-lg border-0 ring-offset-0 focus-visible:ring-1 focus-visible:ring-primary rounded-xl"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <Button 
              type="submit" 
              disabled={isAnalyzing}
              className="absolute right-2 top-2 bottom-2 h-12 px-6 rounded-lg font-semibold transition-all"
            >
              {isAnalyzing ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analizando...
                </div>
              ) : (
                "Validar Enlace"
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Error de conexion o del servidor */}
      {error && (
        <Alert className="z-10 w-full max-w-3xl mb-8 border-red-500/20 bg-red-500/10 text-red-400">
          <XCircle className="h-4 w-4 text-red-500" />
          <AlertTitle className="text-foreground font-medium">Error de análisis</AlertTitle>
          <AlertDescription className="text-sm">{error}</AlertDescription>
        </Alert>
      )}

      {/* Recomendaciones */}
      {!result && !error && (
        <div className="z-10 w-full max-w-3xl grid grid-cols-1 md:grid-cols-2 gap-4 animate-in fade-in slide-in-from-bottom-4 duration-700">
          <Alert className="glass-panel border-white/5 bg-white/5 text-muted-foreground">
            <Info className="h-4 w-4 text-blue-400" />
            <AlertTitle className="text-foreground font-medium">Verifique el candado (SSL)</AlertTitle>
            <AlertDescription className="text-sm">
              Asegúrese de que el enlace comience con "https://" antes de ingresar credenciales.
            </AlertDescription>
          </Alert>
          <Alert className="glass-panel border-white/5 bg-white/5 text-muted-foreground">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <AlertTitle className="text-foreground font-medium">Desconfíe de la urgencia</AlertTitle>
            <AlertDescription className="text-sm">
              Los sitios de phishing suelen presionar con mensajes de "cuenta bloqueada" o "acción inmediata".
            </AlertDescription>
          </Alert>
        </div>
      )}

      {/* Resultados */}
      {result && (
        <div className="z-10 w-full max-w-3xl mt-4 animate-in fade-in zoom-in-95 duration-500">
          <Card className="glass-panel border-0 overflow-hidden">
            {/* Header Result */}
            <div className="p-8 border-b border-white/10 flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-6">
                <div className={`p-4 rounded-full border ${getVerdictColor(result.verdict)}`}>
                  {result.verdict === "Seguro" ? <ShieldCheck className="w-8 h-8" /> : 
                   result.verdict === "Malicioso" ? <ShieldAlert className="w-8 h-8" /> : 
                   <AlertTriangle className="w-8 h-8" />}
                </div>
                <div>
                  <p className="text-sm text-muted-foreground uppercase tracking-wider font-semibold mb-1">
                    Veredicto de Seguridad
                  </p>
                  <h2 className="text-3xl font-bold flex items-center gap-3">
                    {result.verdict}
                  </h2>
                </div>
              </div>
              
              <div className="w-full md:w-auto flex flex-col gap-2">
                <div className="flex justify-between items-center text-sm mb-1">
                  <span className="text-muted-foreground">Score de Riesgo</span>
                  <span className="font-mono font-medium">{result.riskScore}/100</span>
                </div>
                <Progress 
                  value={result.riskScore} 
                  className="h-2 w-full md:w-48 bg-white/10"
                />
              </div>
            </div>

            {/* Validation Breakdown */}
            <CardContent className="p-0">
              <div className="p-6 md:p-8">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Search className="w-5 h-5 text-primary" />
                  Desglose de Análisis
                </h3>
                <div className="grid gap-3">
                  {result.methods.map((method, idx) => (
                    <div key={idx} className="flex items-start md:items-center p-4 rounded-xl bg-white/5 border border-white/5 gap-4 transition-colors hover:bg-white/10">
                      <div className="mt-0.5 md:mt-0">
                        {getStatusIcon(method.status)}
                      </div>
                      <div className="flex-1">
                        <p className="font-medium text-foreground">{method.name}</p>
                        <p className="text-sm text-muted-foreground">{method.detail}</p>
                      </div>
                      <Badge variant="outline" className={`
                        hidden md:inline-flex capitalize
                        ${method.status === 'pass' ? 'text-emerald-400 border-emerald-400/20' : 
                          method.status === 'warn' ? 'text-amber-400 border-amber-400/20' : 
                          'text-red-400 border-red-400/20'}
                      `}>
                        {method.status === 'pass' ? 'Aprobado' : method.status === 'warn' ? 'Advertencia' : 'Crítico'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>

              {/* Acciones */}
              <div className="p-6 bg-white/5 border-t border-white/10 flex justify-end">
                <Button variant="outline" onClick={exportToPDF} className="glass-panel hover:bg-white/10">
                  <Download className="w-4 h-4 mr-2" />
                  Exportar Reporte (PDF)
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </main>
  );
}
