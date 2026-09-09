import { createBrowserRouter } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import DashboardPage   from '@/pages/dashboard/DashboardPage'
import TasksPage       from '@/pages/tasks/TasksPage'
import TaskDetailPage  from '@/pages/tasks/TaskDetailPage'
import RuntimePage     from '@/pages/runtime/RuntimePage'
import FindingsPage    from '@/pages/findings/FindingsPage'
import EvidencePage    from '@/pages/evidence/EvidencePage'
import ReportsPage     from '@/pages/reports/ReportsPage'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true,            element: <DashboardPage /> },
      { path: 'tasks',          element: <TasksPage /> },
      { path: 'tasks/:taskId',  element: <TaskDetailPage /> },
      { path: 'runtime',        element: <RuntimePage /> },
      { path: 'findings',       element: <FindingsPage /> },
      { path: 'evidence',       element: <EvidencePage /> },
      { path: 'reports',        element: <ReportsPage /> },
    ],
  },
])
