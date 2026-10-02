library(shiny)
ui <- fluidPage(textOutput("hello"))
server <- function(input, output, session) {
  output$hello <- renderText(paste("skald r-shiny fixture on R", getRversion()))
}
shinyApp(ui, server)
